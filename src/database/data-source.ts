import 'dotenv/config';
import { DataSource } from 'typeorm';
import { entities } from './entities.js';
import { join } from 'path';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DATABASE_HOST ?? 'localhost',
  port: Number(process.env.DATABASE_PORT ?? 5432),
  username: process.env.DATABASE_USERNAME ?? 'postgres',
  password: process.env.DATABASE_PASSWORD ?? 'postgres',
  database: process.env.DATABASE_NAME ?? 'eauth',
  entities,
  migrations: [join(import.meta.dirname, 'migrations/*{.ts,.js}')],
  synchronize: false,
});
