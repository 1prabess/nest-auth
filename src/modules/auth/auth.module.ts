import { Module } from '@nestjs/common';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { AuthService } from './auth.service.js';
import { AuthController } from './auth.controller.js';
import { LocalStrategy } from './strategies/local.strategy.js';
import { JwtStrategy } from './strategies/jwt.strategy.js';
import { LocalAuthGuard } from './guards/local-auth.guard.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { UserModule } from '../users/user.module.js';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigType } from '@nestjs/config';
import jwtConfig from '../../configs/jwt.config.js';
import { JwtModule } from '@nestjs/jwt';
import { parseDurationToSeconds } from '../../common/utils/duration.util.js';

@Module({
  imports: [
    UserModule,
    PassportModule,
    ConfigModule.forFeature(jwtConfig),
    JwtModule.registerAsync({
      imports: [ConfigModule.forFeature(jwtConfig)],
      inject: [jwtConfig.KEY],
      useFactory: (jwtConfiguration: ConfigType<typeof jwtConfig>) => ({
        secret: jwtConfiguration.accessSecret,
        signOptions: {
          expiresIn: parseDurationToSeconds(jwtConfiguration.accessTtl),
          issuer: jwtConfiguration.issuer,
        },
      }),
    }),
  ],
  providers: [
    PasswordService,
    TokenService,
    AuthService,
    LocalStrategy,
    JwtStrategy,
    LocalAuthGuard,
    JwtAuthGuard,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
