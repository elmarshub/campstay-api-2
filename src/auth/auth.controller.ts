import {
  Body,
  Controller,
  Post,
  Get,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ConfigService } from "@nestjs/config";
import { Request, Response } from "express";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiCookieAuth,
} from "@nestjs/swagger";
import { AuthService } from "./auth.service";
import { RegisterDto } from "./dto/register.dto";
import { LoginDto } from "./dto/login.dto";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";

const REFRESH_COOKIE_NAME = "campstay_refresh_token";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(
    private authService: AuthService,
    private config: ConfigService,
  ) {}

  @ApiOperation({ summary: "Create a new guest account" })
  @ApiResponse({ status: 201, description: "Account created" })
  @ApiResponse({ status: 409, description: "Email already in use" })
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @Post("register")
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @ApiOperation({ summary: "Log in and receive an access token" })
  @ApiResponse({
    status: 200,
    description: "Returns accessToken; sets refresh token as httpOnly cookie",
  })
  @ApiResponse({ status: 401, description: "Invalid email or password" })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post("login")
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken, userId } = await this.authService.login(
      dto,
      req.headers["user-agent"],
      req.ip,
    );

    this.setRefreshCookie(res, refreshToken);

    /*
     * Only the access token goes in the response body. The refresh token
     * lives only in the httpOnly cookie, which client-side JS can't read,
     * protecting it from theft via XSS.
     */
    return { accessToken, userId };
  }

  @ApiOperation({
    summary: "Exchange a valid refresh cookie for a new access token",
  })
  @ApiResponse({
    status: 200,
    description:
      "Returns a new accessToken; sets a new refresh token as httpOnly cookie (rotation)",
  })
  @ApiResponse({ status: 401, description: "Invalid or expired refresh token" })
  @ApiCookieAuth()
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const rawToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!rawToken) {
      throw new UnauthorizedException("No refresh token provided");
    }

    const { accessToken, refreshToken } = await this.authService.refresh(
      rawToken,
      req.headers["user-agent"],
      req.ip,
    );

    this.setRefreshCookie(res, refreshToken);
    return { accessToken };
  }

  @ApiOperation({ summary: "Revoke the current session" })
  @ApiResponse({
    status: 200,
    description: "Session revoked; refresh cookie cleared",
  })
  @ApiCookieAuth()
  @Post("logout")
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const rawToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (rawToken) {
      await this.authService.logout(rawToken);
    }
    res.clearCookie(REFRESH_COOKIE_NAME);
    return { success: true };
  }

  @ApiBearerAuth()
  @ApiOperation({
    summary: "Get the currently logged-in user (requires access token)",
  })
  @ApiResponse({
    status: 200,
    description: "Returns the authenticated user's id and role",
  })
  @ApiResponse({ status: 401, description: "Missing or invalid access token" })
  @UseGuards(JwtAuthGuard)
  @Get("me")
  async me(@CurrentUser() user: { userId: string; role: string }) {
    return user;
  }

  private setRefreshCookie(res: Response, token: string) {
    const expiresIn =
      this.config.get<string>("JWT_REFRESH_EXPIRES_IN") ?? "30d";
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    const maxAge = match
      ? parseInt(match[1], 10) *
        { s: 1000, m: 60000, h: 3600000, d: 86400000 }[match[2]]!
      : 30 * 24 * 60 * 60 * 1000;

    res.cookie(REFRESH_COOKIE_NAME, token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge,
      path: "/api/v1/auth",
    });
  }
}
