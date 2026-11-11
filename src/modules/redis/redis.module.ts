import { Logger, Module } from '@nestjs/common';
import { RedisService } from './redis.service.js';
import { ConfigModule, ConfigType } from '@nestjs/config';
import redisConfig from '../../configs/redis.config.js';
import { REDIS_CLIENT } from './redis.constants.js';
import { createClient } from 'redis';

@Module({
  imports: [ConfigModule.forFeature(redisConfig)],
  exports: [RedisService],
  providers: [
    RedisService,
    {
      provide: REDIS_CLIENT,
      inject: [redisConfig.KEY],
      useFactory: async (redis: ConfigType<typeof redisConfig>) => {
        const logger = new Logger('RedisModule');

        const client = createClient({
          url: `redis://${redis.host}:${redis.port}`,
          ...(redis.password ? { password: redis.password } : {}),
        });

        client.on('error', (error: Error) =>
          logger.error(`Redis error: ${error.message}`),
        );
        client.on('reconnecting', () => logger.warn('Redis is reconnecting'));

        await client.connect();

        logger.log(`Redis connected at ${redis.host}:${redis.port}`);

        return client;
      },
    },
  ],
})
export class RedisModule {}
