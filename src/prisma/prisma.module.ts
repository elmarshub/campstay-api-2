import { Global, Module } from "@nestjs/common";
import { PrismaService } from "./prisma.service";

/**
 * @Global() lets every module inject PrismaService without importing PrismaModule.
 */
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
