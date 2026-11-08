import { PassportStrategy } from '@nestjs/passport';
import type { Request } from 'express';
import { Strategy } from 'passport-local';
import { User } from '../../users/entities/user.entity.js';
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service.js';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true,
    });
  }

  async validate(
    _request: Request,
    email: string,
    password: string,
  ): Promise<User> {
    return this.authService.validateCredentials(email, password);
  }
}
