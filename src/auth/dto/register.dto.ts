import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  Matches,
} from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

/**
 * DTO describing the shape of a registration request body.
 *
 * The @Is... decorators are enforced by the global ValidationPipe in main.ts.
 * Requests that don't match this shape are rejected with a 400 before
 * reaching controller code.
 *
 * @ApiProperty decorators are for Swagger docs only and don't validate.
 * They mirror the validation constraints above so there's one source of truth.
 */
export class RegisterDto {
  @ApiProperty({ example: "martin@example.com" })
  @IsEmail()
  email!: string;

  @ApiProperty({
    example: "Password123",
    description: "Min 8 chars, must include uppercase, lowercase, and a number",
  })
  @IsString()
  @MinLength(8, { message: "Password must be at least 8 characters" })
  /* argon2 has a practical input limit of 72 bytes */
  @MaxLength(72)
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message:
      "Password must contain an uppercase letter, a lowercase letter, and a number",
  })
  password!: string;

  @ApiProperty({ example: "Martin" })
  @IsString()
  @MinLength(1)
  @MaxLength(50)
  firstName!: string;

  @ApiProperty({ example: "Ifeanyi" })
  @IsString()
  @MinLength(1)
  @MaxLength(50)
  lastName!: string;
}
