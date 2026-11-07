import { registerAs } from '@nestjs/config';

export default registerAs('jwtConfig', () => ({
  accessSecret: process.env.JWT_ACCESS_SECRET ?? '',
  accessTtl: process.env.JWT_ACCESS_TTL ?? '15m',
  refreshTtl: process.env.JWT_REFRESH_TTL ?? '30d',
  issuer: process.env.JWT_ISSUER ?? 'nest-auth',
}));
