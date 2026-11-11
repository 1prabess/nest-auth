import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import type { createClient } from 'redis';
import { REDIS_CLIENT } from './redis.constants.js';

export type RedisClient = ConfigType<typeof createClient>;

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);

  constructor(
    @Inject(REDIS_CLIENT)
    private readonly redisClient: RedisClient,
  ) {}

  async get(key: string): Promise<string | null> {
    return this.redisClient.get(key);
  }

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.redisClient.set(key, value, {
      expiration: {
        type: 'EX',
        value: ttlSeconds,
      },
    });
  }

  async del(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  async increment(key: string, ttlSeconds: number): Promise<number> {
    const value = await this.redisClient.incr(key);
    if (value == 1) {
      await this.redisClient.expire(key, ttlSeconds);
    }

    return value;
  }

  async ping(): Promise<string> {
    return this.redisClient.ping();
  }

  onModuleDestroy(): void {
    void this.redisClient.quit();
  }
}
