import { SignOptions } from 'jsonwebtoken';
import { UserRole } from 'src/users/enums/user-role.enum';

export type AccessTokenPayload = {
  userId: number;
  sessionId: number;
  role: UserRole;
};

export type RefreshTokenPayload = {
  sessionId: number;
};
