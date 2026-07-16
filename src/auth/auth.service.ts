import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import * as argon2 from "argon2";
import * as crypto from "crypto";
import { Role } from "@prisma/client";
import { PrismaService } from "../prisma/prisma.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";

type AuthTokens = {
  accessToken: string;
  refreshToken: string;
};

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });
    /*
     * For a production app, consider NOT revealing that the email exists
     * to avoid account enumeration. A clear error is a reasonable trade-off for v1.
     */
    if (existing) {
      throw new ConflictException("An account with this email already exists");
    }

    /*
     * argon2id is the OWASP-recommended password hashing algorithm.
     * It's intentionally slow and memory-hard, making brute-force attacks
     * on a stolen password database expensive.
     */
    const passwordHash = await argon2.hash(dto.password, {
      type: argon2.argon2id,
    });

    const user = await this.prisma.user.create({
      data: {
        email: dto.email.toLowerCase(),
        passwordHash,
        firstName: dto.firstName,
        lastName: dto.lastName,
      },
    });

    // TODO: queue a verification email job (BullMQ + Redis) instead of inline SMTP

    return { id: user.id, email: user.email };
  }

  async login(
    dto: LoginDto,
    userAgent?: string,
    ip?: string,
  ): Promise<AuthTokens & { userId: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });

    /*
     * Return the same error whether the user doesn't exist or the password
     * is wrong. Differentiating would let an attacker discover which emails
     * have accounts (user enumeration).
     */
    const genericError = () =>
      new UnauthorizedException("Invalid email or password");

    /*
     * Run a dummy hash so a non-existent user and a wrong password take
     * roughly the same time to respond (timing-attack mitigation).
     */
    if (!user) {
      await argon2.hash("dummy-password-for-timing");
      throw genericError();
    }

    const passwordValid = await argon2.verify(user.passwordHash, dto.password);
    if (!passwordValid) {
      throw genericError();
    }

    const tokens = await this.issueTokens(user.id, user.role);

    /*
     * Store a hash of the refresh token as a new session row.
     * If the DB leaks, the stored hashes can't be used to log in.
     */
    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash: this.hashToken(tokens.refreshToken),
        userAgent,
        ipAddress: ip,
        expiresAt: this.getRefreshExpiry(),
      },
    });

    return { ...tokens, userId: user.id };
  }

  // ---------- REFRESH (with rotation + reuse detection) ----------
  async refresh(
    rawRefreshToken: string,
    userAgent?: string,
    ip?: string,
  ): Promise<AuthTokens> {
    let payload: { sub: string };
    try {
      payload = this.jwt.verify(rawRefreshToken, {
        secret: this.config.get("JWT_REFRESH_SECRET"),
      });
    } catch {
      throw new UnauthorizedException("Invalid refresh token");
    }

    const tokenHash = this.hashToken(rawRefreshToken);
    const session = await this.prisma.session.findFirst({
      where: { userId: payload.sub, refreshTokenHash: tokenHash },
    });

    /*
     * If the token matches no active session, it may be a replayed token
     * from an attacker who stole a rotated copy. Revoke all sessions for
     * this user and force a full re-login.
     */
    if (!session || session.revokedAt || session.expiresAt < new Date()) {
      await this.prisma.session.updateMany({
        where: { userId: payload.sub, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      throw new UnauthorizedException("Session invalid - please log in again");
    }

    // Rotate: revoke the old session and issue a new refresh token
    await this.prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });

    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: payload.sub },
    });
    const tokens = await this.issueTokens(user.id, user.role);

    await this.prisma.session.create({
      data: {
        userId: user.id,
        refreshTokenHash: this.hashToken(tokens.refreshToken),
        userAgent,
        ipAddress: ip,
        expiresAt: this.getRefreshExpiry(),
      },
    });

    return tokens;
  }

  async logout(rawRefreshToken: string) {
    const tokenHash = this.hashToken(rawRefreshToken);
    await this.prisma.session.updateMany({
      where: { refreshTokenHash: tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async issueTokens(userId: string, role: Role): Promise<AuthTokens> {
    const accessToken = await this.jwt.signAsync(
      { sub: userId, role },
      {
        secret: this.config.get("JWT_ACCESS_SECRET"),
        expiresIn: this.config.get("JWT_ACCESS_EXPIRES_IN"),
      },
    );

    const refreshToken = await this.jwt.signAsync(
      { sub: userId },
      {
        secret: this.config.get("JWT_REFRESH_SECRET"),
        expiresIn: this.config.get("JWT_REFRESH_EXPIRES_IN"),
      },
    );

    return { accessToken, refreshToken };
  }

  /**
   * Hash the refresh token before storing it. SHA-256 is sufficient here
   * because the refresh token is already a long random JWT, not a
   * guessable password that would need argon2's memory-hardness.
   */
  private hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  private getRefreshExpiry(): Date {
    const expiresIn =
      this.config.get<string>("JWT_REFRESH_EXPIRES_IN") ?? "30d";
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    const value = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60000,
      h: 3600000,
      d: 86400000,
    };
    return new Date(Date.now() + value * multipliers[unit]);
  }
}
