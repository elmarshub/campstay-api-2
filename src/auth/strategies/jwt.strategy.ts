import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { ConfigService } from "@nestjs/config";

/**
 * Runs automatically when a request hits a JwtAuthGuard-protected route.
 *
 * 1. Extracts the token from the "Authorization: Bearer <token>" header
 * 2. Verifies its signature against JWT_ACCESS_SECRET
 * 3. If valid, the return value of validate() becomes request.user
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get("JWT_ACCESS_SECRET"),
    });
  }

  async validate(payload: { sub: string; role: string }) {
    /* Keep this lightweight — it runs on every authenticated request */
    return { userId: payload.sub, role: payload.role };
  }
}
