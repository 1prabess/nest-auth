import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { SessionContext } from '../../modules/auth/token.service.js';

export const RequestContext = createParamDecorator(
  (_data: unknown, context: ExecutionContext): SessionContext => {
    const request = context.switchToHttp().getRequest<Request>();

    return {
      userAgent: request.headers['user-agent']?.slice(0, 255) ?? null,
      ipAddress: request.ip ?? null,
    };
  },
);
