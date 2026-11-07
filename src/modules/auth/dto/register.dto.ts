import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    example: 'sthxprabesh@gmail.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '1234567890',
    minLength: 8,
    maxLength: 128,
    description: 'At least 8 characters. Length beats complexity.',
  })
  @IsString()
  @MaxLength(128)
  @MinLength(8)
  password: string;
}
