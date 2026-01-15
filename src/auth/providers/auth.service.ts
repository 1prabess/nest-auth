import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SessionsService } from 'src/sessions/providers/sessions.service';
import { UsersService } from 'src/users/providers/users.service';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { RegisterDto } from '../dtos/register.dto';
import { LoginDto } from '../dtos/login.dto';
import { AuthResponse } from '../interfaces/auth-response.interface';
import {
  AccessTokenPayload,
  RefreshTokenPayload,
} from '../interfaces/jwt-payload.interface';
import { UserRole } from 'src/users/enums/user-role.enum';
import { ONE_DAY_MS } from 'src/common/utils/dates';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private sessionsService: SessionsService,
    private configService: ConfigService,
  ) {}

  // Login a user
  async login(loginDto: LoginDto, userAgent?: string): Promise<AuthResponse> {
    // Find the user by email
    const user = await this.usersService.findByEmail(loginDto.email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    // Check if the password matches
    const valid = await bcrypt.compare(loginDto.password, user.password);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    // Create a session for this login
    const session = await this.sessionsService.create(user.id, userAgent);

    // Generate JWT access & refresh tokens
    const accessToken = this.generateAccessToken(
      user.id,
      session.id,
      user.role,
    );
    const refreshToken = this.generateRefreshToken(session.id);

    // Return tokens
    return { accessToken, refreshToken };
  }

  // Register a new user
  async register(
    registerDto: RegisterDto,
    userAgent?: string,
  ): Promise<AuthResponse> {
    // Create a new user in the database
    const user = await this.usersService.create(registerDto);

    // Create a session for the newly registered user
    const session = await this.sessionsService.create(user.id, userAgent);

    // Generate JWT access & refresh tokens
    const accessToken = this.generateAccessToken(
      user.id,
      session.id,
      user.role,
    );
    const refreshToken = this.generateRefreshToken(session.id);

    // Return tokens
    return { accessToken, refreshToken };
  }

  // Refresh user token
  async refreshUserToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken?: string }> {
    // Verify refresh token and extract payload
    const { payload, error } = this.verifyRefreshToken(refreshToken);
    if (error || !payload) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Find the session
    const session = await this.sessionsService.findById(payload.sessionId);
    if (!session || session.expiresAt.getTime() <= Date.now()) {
      throw new UnauthorizedException('Session expired or invalid');
    }

    // Load user
    const user = await this.usersService.findById(session.user.id);
    if (!user) throw new UnauthorizedException('User not found');

    // Check if the refresh token should be rotated
    const sessionNeedsRefresh =
      session.expiresAt.getTime() - Date.now() <= ONE_DAY_MS;

    // Extend session expiry if session needs to be refreshed and issue a new refresh token
    let newRefreshToken: string | undefined;
    if (sessionNeedsRefresh) {
      await this.sessionsService.extendSession(session.id);
      newRefreshToken = this.generateRefreshToken(session.id);
    }

    // Always issue a new access token
    const accessToken = this.generateAccessToken(
      user.id,
      session.id,
      user.role,
    );

    return { accessToken, refreshToken: newRefreshToken };
  }

  // Generate JWT access token
  private generateAccessToken(
    userId: number,
    sessionId: number,
    role: UserRole,
  ): string {
    const secret = this.configService.get<string>('JWT_ACCESS_SECRET');
    if (!secret)
      throw new Error('JWT_ACCESS_SECRET not defined in environment');

    return jwt.sign({ userId, sessionId, role }, secret, { expiresIn: '15m' });
  }

  // Generate JWT refresh token
  private generateRefreshToken(sessionId: number): string {
    const secret = this.configService.get<string>('JWT_REFRESH_SECRET');
    if (!secret)
      throw new Error('JWT_REFRESH_SECRET not defined in environment');

    return jwt.sign({ sessionId }, secret, { expiresIn: '30d' });
  }

  // Verify accessToken
  verifyAccessToken(token: string): {
    payload: AccessTokenPayload | null;
    error: string | null;
  } {
    const secret = this.configService.get<string>('JWT_ACCESS_SECRET');
    if (!secret) throw new Error('JWT_ACCESS_SECRET not defined');

    try {
      const payload = jwt.verify(token, secret) as AccessTokenPayload;
      return { payload, error: null };
    } catch (err) {
      return {
        payload: null,
        error: err.message,
      };
    }
  }

  // Verify refreshToken
  private verifyRefreshToken(token: string): {
    payload: RefreshTokenPayload | null;
    error: string | null;
  } {
    const secret = this.configService.get<string>('JWT_REFRESH_SECRET');
    if (!secret) throw new Error('JWT_REFRESH_SECRET not defined');

    try {
      const payload = jwt.verify(token, secret) as RefreshTokenPayload;
      return { payload, error: null };
    } catch (err) {
      return {
        payload: null,
        error: err.message,
      };
    }
  }
}
