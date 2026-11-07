import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import jwtConfig from '../../configs/jwt.config.js';
import type { ConfigType } from '@nestjs/config';
import { parseDurationToSeconds } from '../../common/utils/duration.util.js';
import { User } from '../users/entities/user.entity.js';
import { randomUUID } from 'crypto';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  jti: string;
  iat?: number;
  exp?: number;
  iss?: string;
}

export interface AuthTokens {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

@Injectable()
export class TokenService {
  private readonly accessTtlSeconds: number;

  constructor(
    private readonly jwt: JwtService,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
  ) {
    this.accessTtlSeconds = parseDurationToSeconds(jwtConfiguration.accessTtl);
  }

  async issueAccessToken(user: User): Promise<AuthTokens> {
    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      jti: randomUUID(),
    });

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: this.accessTtlSeconds,
    };
  }
}
