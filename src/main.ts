import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { NestExpressApplication } from "@nestjs/platform-express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  /*
   * Trust the first proxy hop so req.ip reflects the real client IP
   * behind nginx, a load balancer, or a PaaS like Railway/Render.
   */
  app.set("trust proxy", 1);

  /* Secure HTTP headers (removes X-Powered-By, sets HSTS, etc) */
  app.use(helmet());

  /* Parse httpOnly refresh-token cookies from incoming requests */
  app.use(cookieParser());

  /* Restrict origins to our frontend and allow credentials cross-origin */
  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  });

  /*
   * ValidationPipe runs on every request body before it reaches controllers:
   * - whitelist: strips fields not defined in the DTO
   * - forbidNonWhitelisted: throws on extra fields instead of silently stripping
   * - transform: converts plain JSON into class instances so decorators work
   */
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.setGlobalPrefix("api/v1");

  /*
   * Swagger docs are auto-generated from controller and DTO decorators.
   * Skipped in production to avoid exposing API structure to attackers.
   */
  if (process.env.NODE_ENV !== "production") {
    const config = new DocumentBuilder()
      .setTitle("CampStay API")
      .setDescription("Reservation platform API docs")
      .setVersion("1.0")
      .addBearerAuth()
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup("api/docs", app, document);
  }

  const port = process.env.PORT || 4000;
  await app.listen(port);
  console.log(`CampStay API running on http://localhost:${port}/api/v1`);
}
bootstrap();
