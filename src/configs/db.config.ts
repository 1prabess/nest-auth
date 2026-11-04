import { registerAs } from '@nestjs/config';
import { LogLevel } from 'typeorm';

export default registerAs('dbConfig', () => {
  const logging: LogLevel[] =
    process.env.NODE_ENV === 'development'
      ? ['warn', 'error', 'schema']
      : ['error'];

  return {
    host: process.env.DATABASE_HOST ?? 'localhost',
    port: Number(process.env.DATABASE_PORT ?? 5432),
    username: process.env.DATABASE_USERNAME ?? 'postgres',
    password: process.env.DATABASE_PASSWORD ?? '',
    name: process.env.DATABASE_NAME ?? 'nest-auth',
    logging,
  };
});
