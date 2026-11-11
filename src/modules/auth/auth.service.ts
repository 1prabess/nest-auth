import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../users/user.service.js';
import { PasswordService } from './password.service.js';
import { AuthTokens, SessionContext, TokenService } from './token.service.js';
import { RegisterDto } from './dto/register.dto.js';
import { User } from '../users/entities/user.entity.js';

const DUMMY_PASSWORD_HASH =
  '$argon2id$v=19$m=19456,p=1,t=2$xedFCuQ9eRLNuOWIz74/ZQ$dUKQBnXKZPD7E6JUHS8KGj/ScfbOLFilKZxz83hcBkY';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) {}

  async register(
    registerDto: RegisterDto,
    context: SessionContext,
  ): Promise<AuthTokens> {
    const existing = await this.userService.findByEmail(registerDto.email);

    if (existing) {
      throw new ConflictException('An account with this email already exists');
    }

    const passwordHash = await this.passwordService.hashPassword(
      registerDto.password,
    );

    const user = await this.userService.create({
      email: registerDto.email,
      passwordHash,
    });

    return this.tokenService.issueTokenPair(user, context);
  }

  async login(user: User, context: SessionContext): Promise<AuthTokens> {
    return this.tokenService.issueTokenPair(user, context);
  }

  async issueAccessToken(
    user: User,
    context: SessionContext,
  ): Promise<AuthTokens> {
    return this.tokenService.issueTokenPair(user, context);
  }

  async validateCredentials(email: string, password: string): Promise<User> {
    const user = await this.userService.findByEmail(email);

    if (!user || !user.passwordHash) {
      await this.passwordService.verifyPassword(DUMMY_PASSWORD_HASH, password);
      throw new UnauthorizedException('Invalid email or password');
    }

    const passwordMatches = await this.passwordService.verifyPassword(
      user.passwordHash,
      password,
    );

    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid email or password');
    }

    return user;
  }

  async refresh(
    rawRefreshToken: string,
    context: SessionContext,
  ): Promise<AuthTokens> {
    const stored = await this.tokenService.findRefreshToken(rawRefreshToken);
    if (!stored) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (stored.revokedAt) {
      await this.tokenService.revokeRefreshToken(
        stored.sessionId,
        'reuse_detected',
      );
      throw new UnauthorizedException('Refresh token has already been used');
    }

    if (stored.expiresAt.getTime() <= Date.now()) {
      throw new UnauthorizedException('Refresh token has expired');
    }

    const user = await this.userService.findById(stored.user_id);

    if (!user) {
      throw new UnauthorizedException('Account no longer exists');
    }

    await this.tokenService.revokeRefreshToken(stored.id, 'rotated');

    return this.tokenService.issueTokenPair(user, context, stored.sessionId);
  }
}
