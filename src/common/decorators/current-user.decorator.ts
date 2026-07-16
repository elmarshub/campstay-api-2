import { createParamDecorator, ExecutionContext } from "@nestjs/common";

/**
 * Usage: getProfile(@CurrentUser() user: { userId: string; role: string }) { ... }
 * Reads request.user, which is populated by JwtStrategy.validate().
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
