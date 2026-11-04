import { z } from 'zod';

export const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  API_PREFIX: z.string().min(1).default('api'),
  CORS_ORIGINS: z.string().default(''),

  DATABASE_URL: z
    .string()
    .min(1, 'DATABASE_URL is required')
    .refine((value) => value.startsWith('postgresql://'), {
      message: 'DATABASE_URL must start with postgresql://',
    }),

  REDIS_HOST: z.string().min(1).default('localhost'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),

  JWT_ACCESS_SECRET: z
    .string()
    .min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  JWT_ACCESS_TTL: z.string().min(2).default('15m'),
  JWT_REFRESH_TTL: z.string().min(2).default('30d'),
  JWT_ISSUER: z.string().min(1).default('nest-auth'),
});
