import { Module } from '@nestjs/common';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import dbConfig from '../configs/db.config.js';
import { entities } from './entities.js';
import { join } from 'path';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule.forFeature(dbConfig)],
      inject: [dbConfig.KEY],
      useFactory: (db: ConfigType<typeof dbConfig>) => ({
        type: 'postgres' as const,
        host: db.host,
        port: db.port,
        username: db.username,
        password: db.password,
        database: db.name,
        entities,
        migrations: [join(import.meta.dirname, 'migrations/*{.ts,.js}')],
        synchronize: false,
        migrationsRun: false,
        logging: db.logging,
      }),
    }),
  ],
})
export class DatabaseModule {}
