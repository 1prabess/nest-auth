import { ApiProperty } from '@nestjs/swagger';

export class UserResponseDto {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ example: 'ada@example.com' })
  email: string;

  @ApiProperty({ example: true })
  emailVerified: boolean;

  @ApiProperty({ example: '2026-11-01T09:00:00.000Z' })
  createdAt: Date;
}
