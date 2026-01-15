import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { map, Observable } from 'rxjs';
import { ResponseMessage } from 'src/common/decorators/response-message.decorator';

@Injectable()
export class SuccessInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        const message = this.reflector.get(
          ResponseMessage,
          context.getHandler() || 'Request successful',
        );

        return { status: 'success', message, data };
      }),
    );
  }
}
