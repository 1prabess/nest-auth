import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthenticatedRequest } from '../../modules/auth/authenticated-request.js';

export const CurrentToken = createParamDecorator(
  (
    _data: unknown,
    context: ExecutionContext,
  ): AuthenticatedRequest['jwtPaylod'] => {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    return request.jwtPaylod;
  },
);
