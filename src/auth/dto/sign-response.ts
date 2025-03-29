import { Field, ObjectType } from '@nestjs/graphql';
import { User } from '../entities/user.entity';


@ObjectType()
export class SignResponse {
  @Field()
  accessToken:string;

  @Field()
  refreshToken:string

  @Field(()=> User )
  user:User
}
