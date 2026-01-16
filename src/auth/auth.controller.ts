import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './providers/auth.service';
import { LoginDto } from './dtos/login.dto';
import type { Request, Response } from 'express';
import { ResponseMessage } from 'src/common/decorators/response-message.decorator';
import { RegisterDto } from './dtos/register.dto';
import {
  clearAuthCookies,
  getAccessTokenCookieOption,
  getRefreshTokenCookieOption,
  setAuthCookies,
} from 'src/common/utils/cookies';
import { ApiOperation } from '@nestjs/swagger';

@Controller('auth')
@ResponseMessage('Login successful')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Login a user' })
  @Post('/login')
  @ResponseMessage('Login successful')
  async login(
    @Body() loginDto: LoginDto,
    @Headers('user-agent') userAgent: string,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    // Get access & refresh tokens from the service
    const { accessToken, refreshToken } = await this.authService.login(
      loginDto,
      userAgent,
    );

    // Set access & refresh tokens in cookies
    setAuthCookies({ response, refreshToken, accessToken });
    return;
  }

  @ApiOperation({ summary: 'Registers a user' })
  @Post('/register')
  @ResponseMessage('Registration successful')
  async register(
    @Body() registerDto: RegisterDto,
    @Req() request: Request,
    @Res({
      passthrough: true,
    })
    response: Response,
  ): Promise<void> {
    // Get user agent from request
    const userAgent = request.headers['user-agent'];

    // Get access & refresh tokens from the service
    const { accessToken, refreshToken } = await this.authService.register(
      registerDto,
      userAgent,
    );

    // Set access & refresh tokens in cookies
    setAuthCookies({ response, refreshToken, accessToken });
    return;
  }

  @ApiOperation({ summary: 'Logs out a user' })
  @Get('/logout')
  @ResponseMessage('Logout successful')
  @Get()
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    // Get access token from cookies
    const accessToken = request.cookies?.accessToken;
    if (!accessToken) throw new UnauthorizedException('Access token missing');

    await this.authService.logout(accessToken);

    // Clear cookies
    clearAuthCookies(response);
    return;
  }

  @ApiOperation({ summary: 'Refresh user access token' })
  @Get('/refresh')
  @ResponseMessage('Token refresh successful')
  async refreshToken(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ): Promise<void> {
    // Get refresh token from cookies
    const refreshToken = request.cookies?.refreshToken;
    if (!refreshToken) throw new UnauthorizedException('Refresh token missing');

    // Get access & optionally refresh token from the service
    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshUserToken(refreshToken);

    // Set new refresh token in cookies if it was generated
    if (newRefreshToken) {
      response.cookie(
        'refreshToken',
        newRefreshToken,
        getRefreshTokenCookieOption(),
      );
    }

    // Set new access token in cookies
    response.cookie('accessToken', accessToken, getAccessTokenCookieOption());
    return;
  }
}
