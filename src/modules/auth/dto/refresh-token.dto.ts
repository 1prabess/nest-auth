import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'The refresh token issued alongside the access token',
  })
  @IsString()
  @MinLength(20)
  refreshToken: string;
}
