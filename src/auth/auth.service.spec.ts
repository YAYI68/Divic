import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { PrismaService } from 'src/database/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';
import { JwtPayload } from './interfaces/jwt.interface';
import { SignInput, BiometricInput } from './dto/sign-inputs';

describe('AuthService', () => {
  let authService: AuthService;
  let prismaServiceMock: Partial<PrismaService>;
  let jwtServiceMock: Partial<JwtService>;

  beforeEach(async () => {
    prismaServiceMock = {
      user: {
        findUnique: jest.fn(),
        create: jest.fn(),
      },
    };

    jwtServiceMock = {
      signAsync: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaServiceMock },
        { provide: JwtService, useValue: jwtServiceMock },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(authService).toBeDefined();
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const SignInput: SignInput = {
        email: 'test@example.com',
        password: 'password',
      };
      const mockUser = { id: 1, email: SignInput.email, password: 'hashedPassword', biometricKey: 'biometricKey' };
      const mockJwtPayload: JwtPayload = { userId: mockUser.id };
      const mockTokens = { accessToken: 'accessToken', refreshToken: 'refreshToken' };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce(null);
      bcrypt.hash = jest.fn().mockResolvedValueOnce('hashedPassword');
      prismaServiceMock.user.create = jest.fn().mockResolvedValueOnce(mockUser);
      jwtServiceMock.signAsync = jest.fn().mockResolvedValueOnce(mockTokens.accessToken).mockResolvedValueOnce(mockTokens.refreshToken);

      const result = await authService.create(SignInput);

      expect(result).toEqual({ ...mockTokens, user: { id: mockUser.id, email: mockUser.email, biometricKey: mockUser.biometricKey } });
    });

    it('should throw ConflictException if user already exists', async () => {
      const SignInput: SignInput = {
        email: 'test@example.com',
        password: 'password',
      };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce({ email: SignInput.email });

      await expect(authService.create(SignInput)).rejects.toThrow(ConflictException);
    });
  });

  describe('login', () => {
    it('should log in user with valid credentials', async () => {
      const loginInput: SignInput = {
        email: 'test@example.com',
        password: 'password',
      };
      const mockUser = { id: 1, email: loginInput.email, password: 'hashedPassword', biometricKey: 'biometricKey' };
      const mockJwtPayload: JwtPayload = { userId: mockUser.id };
      const mockTokens = { accessToken: 'accessToken', refreshToken: 'refreshToken' };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce(mockUser);
      bcrypt.compare = jest.fn().mockResolvedValueOnce(true);
      jwtServiceMock.signAsync = jest.fn().mockResolvedValueOnce(mockTokens.accessToken).mockResolvedValueOnce(mockTokens.refreshToken);

      const result = await authService.login(loginInput);

      expect(result).toEqual({ ...mockTokens, user: { id: mockUser.id, email: mockUser.email, biometricKey: mockUser.biometricKey } });
    });

    it('should throw BadRequestException if invalid credentials', async () => {
      const loginInput: SignInput = {
        email: 'test@example.com',
        password: 'password',
      };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce(null);

      await expect(authService.login(loginInput)).rejects.toThrow(BadRequestException);
    });
  });

  describe('bioLogin', () => {
    it('should log in user with valid biometric key', async () => {
      const biometricInput: BiometricInput = {
        biometricKey: 'biometricKey',
      };
      const mockUser = { id: 1, email: 'test@example.com', password: 'hashedPassword', biometricKey: biometricInput.biometricKey };
      const mockJwtPayload: JwtPayload = { userId: mockUser.id };
      const mockTokens = { accessToken: 'accessToken', refreshToken: 'refreshToken' };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce(mockUser);
      jwtServiceMock.signAsync = jest.fn().mockResolvedValueOnce(mockTokens.accessToken).mockResolvedValueOnce(mockTokens.refreshToken);

      const result = await authService.bioLogin(biometricInput);

      expect(result).toEqual({ ...mockTokens, user: { id: mockUser.id, email: mockUser.email, biometricKey: mockUser.biometricKey } });
    });

    it('should throw BadRequestException if invalid biometric key', async () => {
      const biometricInput: BiometricInput = {
        biometricKey: 'invalidBiometricKey',
      };

      prismaServiceMock.user.findUnique = jest.fn().mockResolvedValueOnce(null);

      await expect(authService.bioLogin(biometricInput)).rejects.toThrow(BadRequestException);
    });
  });


});
