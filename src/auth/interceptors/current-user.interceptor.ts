import {
    NestInterceptor,
    ExecutionContext,
    CallHandler,
} from '@nestjs/common';
import { Injectable } from '@nestjs/common/decorators';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class CurrentUserInterceptor implements NestInterceptor {
   constructor( ){}

  async intercept(context: ExecutionContext, next: CallHandler<any>) {
       // Run before any route handlers
       const ctx = GqlExecutionContext.create(context);
       const request = ctx.getContext().req
       const token = request.headers.authorization?.replace('Bearer ','').trim();
       if(token){
           request.token = token
       }
      
       return next.handle()
   }
}
