import { IsNotEmpty, IsOptional, IsString } from "class-validator";

export class CreateAuthDto {
    @IsString()
    @IsNotEmpty()
    email:string

    @IsString()
    @IsNotEmpty()
    password:string

    @IsOptional()
    biometricKey:string
}
export class LoginAuthDto{
    @IsString()
    @IsNotEmpty()
    email:string

    @IsString()
    @IsNotEmpty()
    password:string
}

export class LoginAuthBiometricDto{
    @IsString()
    @IsNotEmpty()
    biometricKey:string
}

