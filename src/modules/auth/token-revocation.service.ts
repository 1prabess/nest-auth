import { Injectable } from '@nestjs/common';
import { RedisService } from '../redis/redis.service.js';
import { redisConfig } from '../redis/redis-keys.js';

@Injectable()
export class TokenRevocationService {
  constructor(private readonly redisService: RedisService) {}

  async revoke(jti: string, expiresAt: number): Promise<void> {
    const remainingSeconds = Math.floor(expiresAt - Date.now() / 1000);

    if (remainingSeconds <= 0) {
      return;
    }

    await this.redisService.set(
      redisConfig.revokedAccessToken.key(jti),
      '1',
      remainingSeconds,
    );
  }

  async isRevoked(jti: string): Promise<boolean> {
    const value = await this.redisService.get(
      redisConfig.revokedAccessToken.key(jti),
    );

    return value !== null;
  }
}
