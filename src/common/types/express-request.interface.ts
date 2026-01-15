import { Request } from 'express';
import { UserRole } from 'src/users/enums/user-role.enum';

export interface AuthenticatedRequest extends Request {
  userId: number;
  sessionId: number;
  role: UserRole;
}
