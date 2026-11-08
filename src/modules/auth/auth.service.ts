import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from '../users/user.service.js';
import { PasswordService } from './password.service.js';
import { AuthTokens, TokenService } from './token.service.js';
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

  async register(registerDto: RegisterDto): Promise<AuthTokens> {
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

    return this.tokenService.issueAccessToken(user);
  }

  async issueAccessToken(user: User): Promise<AuthTokens> {
    return this.tokenService.issueAccessToken(user);
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
}
