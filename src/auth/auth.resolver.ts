import { AuthService } from './auth.service';
import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { Auth } from './entities/auth.entity';
import { BiometricInput, SignInput } from './dto/sign-inputs';
import { SignResponse } from './dto/sign-response';
import { User } from './entities/user.entity';
import { CurrentUser } from './decorators/current-user.decorator';
import { CurrentUserInterface } from './interfaces/current-user.interface';
import { UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './guard/jwt-auth.guard';
SignInput
@Resolver(() => Auth)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}
  
  @Mutation(() => SignResponse)
  signup(@Args('signInput') signInput: SignInput) {
    return this.authService.create(signInput);
  }

  @Mutation(() => SignResponse)
  login(@Args('loginInput') loginInput: SignInput) {
    return this.authService.login(loginInput);
  }

  @Mutation(() => SignResponse)
  bioLogin(@Args('biometricInput') biometricInput: BiometricInput) {
    return this.authService.bioLogin(biometricInput);
  }

  @UseGuards(JwtAuthGuard)
  @Query(() => User)
  profile(@CurrentUser() user: CurrentUserInterface) {
    return this.authService.findOne(user.userId);
  }

}

