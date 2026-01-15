import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { AuthService } from 'src/auth/providers/auth.service';
import { AuthenticatedRequest } from 'src/common/types/express-request.interface';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: AuthenticatedRequest = context.switchToHttp().getRequest();

    // Get access token from the cookies
    const accessToken = request.cookies?.accessToken;
    if (!accessToken) throw new UnauthorizedException('Access token missing');

    // Verify access token and get payload
    const { payload, error } = this.authService.verifyAccessToken(accessToken);
    if (error || !payload) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    // Attach userId, sessionId & role to the request
    request.userId = payload.userId;
    request.sessionId = payload.sessionId;
    request.role = payload.role;

    return true;
  }
}
