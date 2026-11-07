import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  MaxLength,
} from 'class-validator/types/decorator/decorators.js';

export class LoginDto {
  @ApiProperty({ example: 'sthxprabesh@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: '1234567890' })
  @IsString()
  @MaxLength(128)
  password: string;
}
