import { Request } from 'express';
import { User } from '../users/entities/user.entity.js';
import { AccessTokenPayload } from './token.service.js';

export interface AuthenticatedRequest extends Request {
  user: User;
  jwtPaylod: AccessTokenPayload;
}
