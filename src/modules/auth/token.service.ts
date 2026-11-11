import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import jwtConfig from '../../configs/jwt.config.js';
import type { ConfigType } from '@nestjs/config';
import { parseDurationToSeconds } from '../../common/utils/duration.util.js';
import { User } from '../users/entities/user.entity.js';
import { randomUUID } from 'crypto';
import {
  generateOpaqueToken,
  hashToken,
} from '../../common/utils/opaque-token.util.js';
import { InjectRepository } from '@nestjs/typeorm';
import { RefreshToken } from './entities/refresh-token.entity.js';
import { Repository } from 'typeorm';

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
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

export interface SessionContext {
  userAgent: string | null;
  ipAddress: string | null;
}

export type RevocationReason =
  'rotated' | 'logout' | 'logout_all' | 'reuse_detected';

@Injectable()
export class TokenService {
  private readonly accessTtlSeconds: number;
  private readonly refreshTtlSeconds: number;

  constructor(
    private readonly jwt: JwtService,
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,

    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepo: Repository<RefreshToken>,
  ) {
    this.accessTtlSeconds = parseDurationToSeconds(jwtConfiguration.accessTtl);
    this.refreshTtlSeconds = parseDurationToSeconds(
      jwtConfiguration.refreshTtl,
    );
  }

  async issueTokenPair(
    user: User,
    context: SessionContext,
    sessionId?: string,
  ): Promise<AuthTokens> {
    const resolvedSessionId = sessionId ?? randomUUID();
    const refreshToken = generateOpaqueToken();

    await this.refreshTokenRepo.save({
      user_id: user.id,
      tokenHash: hashToken(refreshToken),
      sessionId: resolvedSessionId,
      expiresAt: new Date(Date.now() + this.refreshTtlSeconds * 1000),
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
    });

    const accessToken = await this.jwt.signAsync({
      sub: user.id,
      email: user.email,
      jti: randomUUID(),
      sessionId: resolvedSessionId,
    });

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.accessTtlSeconds,
    };
  }

  async findRefreshToken(
    rawRefreshToken: string,
  ): Promise<RefreshToken | null> {
    return this.refreshTokenRepo.findOneBy({
      tokenHash: hashToken(rawRefreshToken),
    });
  }

  async revokeRefreshToken(
    id: string,
    reason: RevocationReason,
  ): Promise<void> {
    await this.refreshTokenRepo.update(id, {
      revokedAt: new Date(),
      revokedReason: reason,
    });
  }
}
