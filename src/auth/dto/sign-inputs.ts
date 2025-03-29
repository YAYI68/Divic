import { Field, InputType } from '@nestjs/graphql';
import { IsNotEmpty, IsString } from 'class-validator';


@InputType()
export class SignInput {
  @IsNotEmpty() 
  @IsString()
  @Field()
  email:string;
  
  @IsNotEmpty()
  @IsString()
  @Field()
  password:string
  
}

@InputType()
export class BiometricInput {
  @IsNotEmpty() 
  @IsString()
  @Field()
  biometricKey:string;
  
  
}

