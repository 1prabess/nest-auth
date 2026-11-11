import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { RegisterDto } from './dto/register.dto.js';
import type { AuthTokens, SessionContext } from './token.service.js';
import { ApiBearerAuth, ApiBody, ApiOperation } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto.js';
import { LocalAuthGuard } from './guards/local-auth.guard.js';
import { CurrentUser } from '../../common/decorators/current-user.decorator.js';
import { User } from '../users/entities/user.entity.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { UserResponseDto } from '../users/dto/user-response.dto.js';
import { toUserResponse } from '../users/user.mapper.js';
import { RequestContext } from '../../common/decorators/request-context.decorator.js';
import { RefreshTokenDto } from './dto/refresh-token.dto.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Create an account and receive an access token' })
  register(
    @Body() registerDto: RegisterDto,
    @RequestContext() context: SessionContext,
  ): Promise<AuthTokens> {
    return this.authService.register(registerDto, context);
  }

  @Post('login')
  @UseGuards(LocalAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: LoginDto })
  @ApiOperation({ summary: 'Exchange credentials for an access token' })
  login(
    @CurrentUser() user: User,
    @RequestContext() context: SessionContext,
  ): Promise<AuthTokens> {
    return this.authService.login(user, context);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Rotate a refresh token and receive a new token pair',
  })
  refresh(
    @Body() dto: RefreshTokenDto,
    @RequestContext() context: SessionContext,
  ): Promise<AuthTokens> {
    return this.authService.refresh(dto.refreshToken, context);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Return the authenticated user' })
  me(@CurrentUser() user: User): UserResponseDto {
    return toUserResponse(user);
  }
}
