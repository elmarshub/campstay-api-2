import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

/**
 * Apply @UseGuards(JwtAuthGuard) to any controller or route to require
 * a valid access token before the request is allowed through.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {}
