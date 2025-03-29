import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { JwtStrategy } from './strategies/jwt.strategy';
import { CurrentUserInterceptor } from './interceptors/current-user.interceptor';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports:[
    PassportModule
  ],
  providers: [AuthResolver,AuthService, JwtStrategy, JwtService,{
    provide: APP_INTERCEPTOR,
    useClass: CurrentUserInterceptor,
  },],
})
export class AuthModule {}
