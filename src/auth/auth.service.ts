import {
  BadRequestException,
  ConflictException,
  HttpException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from './interfaces/jwt.interface';
import { jwtConstants } from './contants/jwt-constant';
import { BiometricInput, SignInput } from './dto/sign-inputs';

@Injectable()
export class AuthService {
  private logger = new Logger(AuthService.name);
  constructor(
    private readonly prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  private async getTokens(payload: JwtPayload) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: jwtConstants.secret,
        expiresIn: '5m',
      }),
      this.jwtService.signAsync(payload, {
        secret: jwtConstants.secret,
        expiresIn: '7d',
      }),
    ]);
    return { accessToken, refreshToken };
  }

  async hashData(data: string) {
    const salt = await bcrypt.genSalt();
    const hashData = await bcrypt.hash(data, salt);
    return hashData;
  }

  // To verify the hash function
  async verifyHash(data: string, hashData: string) {
    const isValid = await bcrypt.compare(data, hashData);
    return isValid;
  }

  async create(SignInput: SignInput) {
    try{
      const existUser = await this.prisma.user.findUnique({
        where: { email: SignInput.email },
      });
      if (existUser) {
        throw new ConflictException('Email already exists');
      }
  
      const hashpassword = await this.hashData(SignInput.password);
      const hashBiometricKey = await this.hashData(SignInput.email)
      const user = await this.prisma.user.create({
        data: {
          ...SignInput,
          password: hashpassword,
          biometricKey: hashBiometricKey,
        },
      });
      const payload: JwtPayload = {
        userId: user.id,
      };
      const token = await this.getTokens(payload);
      this.logger.log('User Sign up Successfully')
      return { ...token,user:{id:user.id,email:user.email,biometricKey:user.biometricKey} };
    }
    catch(error){
      this.logger.error('Error occur on user signup')
      throw new BadRequestException(error.message)
    }

  }

  async login(loginInput: SignInput) {
    try {
      const { email, password } = loginInput;
      const user = await this.prisma.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new BadRequestException('invalid email/password');
      }
      const isValid = await this.verifyHash(password, user.password);
      if(!isValid){
        throw new BadRequestException('invalid email/password');
      }
        const { id } = user;
        const payload: JwtPayload = { userId: id };
        const token = await this.getTokens(payload);
        this.logger.log('User login  successfully')
        return { ...token,user:{id:user.id,email:user.email,biometricKey:user.biometricKey} };
  
    } catch (error) {
      this.logger.error('Error occur on user login')
      if (error instanceof HttpException) {
        throw new HttpException(error.message, error.getStatus());
      }
      throw error;
    }
  }
  async bioLogin(biometricInput: BiometricInput) {
    try {
      const { biometricKey } = biometricInput;
      const user = await this.prisma.user.findUnique({
        where: { biometricKey },
      });
      if (!user) {
        throw new BadRequestException('invalid email/password');
      }
        const { id } = user;
        const payload: JwtPayload = { userId: id };
        const token = await this.getTokens(payload);
        this.logger.log('User login using biometric successfully')
        return { ...token,user:{id:user.id,email:user.email,biometricKey:user.biometricKey} };
    } catch (error) {
      this.logger.error('Error occur on user login with biometric')
      if (error instanceof HttpException) {
        throw new HttpException(error.message, error.getStatus());
      }
      throw error;
    }
  }

  findOne(id: number) {
    try{
       const user = this.prisma.user.findUnique({where:{
        id:id
       }})
       if(!user){
        throw new BadRequestException('User not found');
       }
       this.logger.log('User fetched  successfully')
       return user
    }
    catch(error){
      this.logger.error('Error occur on fetching user')
      if (error instanceof HttpException) {
        throw new HttpException(error.message, error.getStatus());
      }
      throw error;
    }  
  }
}
