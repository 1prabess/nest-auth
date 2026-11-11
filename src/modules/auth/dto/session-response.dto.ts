import { ApiProperty } from '@nestjs/swagger';

export class SessionResponseDto {
  @ApiProperty({ format: 'uuid' })
  id: string;

  @ApiProperty({ format: 'uuid' })
  sessionId: string;

  @ApiProperty({
    description: 'True when this is the session making the request',
  })
  current: boolean;

  @ApiProperty({
    nullable: true,
    example: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
  })
  userAgent: string | null;

  @ApiProperty({ nullable: true, example: '203.0.113.42' })
  ipAddress: string | null;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  expiresAt: Date;
}
