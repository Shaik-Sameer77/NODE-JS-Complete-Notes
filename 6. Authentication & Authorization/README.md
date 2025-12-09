# Authentication & Authorization - Comprehensive Guide

## 📚 Table of Contents
- [Introduction](#introduction)
- [JWT Authentication](#jwt-authentication)
- [Access Token + Refresh Token](#access-token--refresh-token)
- [Password Hashing](#password-hashing)
- [Session Authentication](#session-authentication)
- [OAuth 2.0 & OpenID Connect](#oauth-20--openid-connect)
- [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
- [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
- [Email Login / OTP](#email-login--otp)
- [Secure Cookie Flags](#secure-cookie-flags)
- [Refresh Token Rotation](#refresh-token-rotation)
- [Interview Questions](#interview-questions)
- [Real-World Scenarios](#real-world-scenarios)

## Introduction

Authentication and Authorization are critical components of modern web applications. This guide covers production-grade security patterns, latest best practices, and real-world implementation strategies for senior developers.

## JWT Authentication

### 🔐 JWT Fundamentals

```typescript
// types/auth.types.ts
export interface JwtPayload {
  sub: string;           // Subject (user ID)
  email: string;
  role: UserRole;
  permissions: string[];
  iat?: number;          // Issued at
  exp?: number;          // Expiration time
  jti?: string;          // JWT ID (for token revocation)
  iss?: string;          // Issuer
  aud?: string;          // Audience
}

export interface JwtTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}
```

### 🛠️ JWT Implementation

```typescript
// services/jwt.service.ts
import jwt from 'jsonwebtoken';
import { randomBytes, createHash } from 'crypto';
import { JwtPayload, JwtTokens } from '@/types/auth.types';

export class JwtService {
  private readonly accessTokenSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly issuer: string;
  private readonly audience: string;

  constructor() {
    this.accessTokenSecret = process.env.JWT_ACCESS_SECRET!;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET!;
    this.issuer = process.env.JWT_ISSUER || 'your-app';
    this.audience = process.env.JWT_AUDIENCE || 'your-app-users';
    
    // Validate configuration
    if (!this.accessTokenSecret || !this.refreshTokenSecret) {
      throw new Error('JWT secrets must be configured');
    }
  }

  // Generate JWT ID for token tracking
  private generateJti(): string {
    return randomBytes(16).toString('hex');
  }

  // Create access token (short-lived)
  async createAccessToken(payload: Partial<JwtPayload>): Promise<string> {
    const jwtPayload: JwtPayload = {
      sub: payload.sub!,
      email: payload.email!,
      role: payload.role!,
      permissions: payload.permissions || [],
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 minutes
      jti: this.generateJti(),
      iss: this.issuer,
      aud: this.audience
    };

    return jwt.sign(jwtPayload, this.accessTokenSecret, {
      algorithm: 'HS256',
      header: {
        alg: 'HS256',
        typ: 'JWT'
      }
    });
  }

  // Create refresh token (long-lived, stored in database)
  async createRefreshToken(userId: string): Promise<string> {
    const payload = {
      sub: userId,
      jti: this.generateJti(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60), // 7 days
      iss: this.issuer,
      aud: this.audience,
      type: 'refresh'
    };

    return jwt.sign(payload, this.refreshTokenSecret, {
      algorithm: 'HS256'
    });
  }

  // Verify access token
  async verifyAccessToken(token: string): Promise<JwtPayload> {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        algorithms: ['HS256'],
        issuer: this.issuer,
        audience: this.audience,
        clockTolerance: 30 // 30 seconds leeway
      }) as JwtPayload;

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenExpiredError('Access token expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new InvalidTokenError('Invalid access token');
      }
      throw error;
    }
  }

  // Verify refresh token
  async verifyRefreshToken(token: string): Promise<{ sub: string; jti: string }> {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        algorithms: ['HS256'],
        issuer: this.issuer,
        audience: this.audience,
        clockTolerance: 30
      }) as { sub: string; jti: string };

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenExpiredError('Refresh token expired');
      }
      throw new InvalidTokenError('Invalid refresh token');
    }
  }

  // Decode token without verification (for debugging)
  decodeToken(token: string): JwtPayload | null {
    try {
      return jwt.decode(token) as JwtPayload;
    } catch {
      return null;
    }
  }

  // Generate token pair
  async generateTokens(user: User): Promise<JwtTokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.createAccessToken({
        sub: user.id,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }),
      this.createRefreshToken(user.id)
    ]);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 15 * 60 // 15 minutes in seconds
    };
  }
}
```

### 🔒 Advanced JWT Security

```typescript
// services/jwt-security.service.ts
import jwt, { SignOptions } from 'jsonwebtoken';
import { redis } from '@/config/redis';

export class JwtSecurityService {
  private readonly keyRotationInterval = 7 * 24 * 60 * 60 * 1000; // 7 days
  private currentKeyId = 'current';
  private previousKeyId: string | null = null;

  // Key rotation for JWT secrets
  async rotateKeys(): Promise<void> {
    const newKeyId = `key_${Date.now()}`;
    const newSecret = randomBytes(64).toString('hex');
    
    // Store new key in Redis with expiration
    await redis.setex(
      `jwt:key:${newKeyId}`,
      2 * this.keyRotationInterval / 1000, // Double the rotation interval
      newSecret
    );
    
    // Update pointers
    this.previousKeyId = this.currentKeyId;
    this.currentKeyId = newKeyId;
    
    // Schedule next rotation
    setTimeout(() => this.rotateKeys(), this.keyRotationInterval);
  }

  // Sign token with key ID in header (JWK-like pattern)
  async signWithKeyRotation(
    payload: object,
    options: SignOptions = {}
  ): Promise<string> {
    const secret = await this.getCurrentSecret();
    const header = {
      alg: 'HS256',
      typ: 'JWT',
      kid: this.currentKeyId
    };

    return jwt.sign(payload, secret, {
      ...options,
      header
    });
  }

  // Verify token with key rotation support
  async verifyWithKeyRotation(token: string): Promise<any> {
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded || !decoded.header.kid) {
      throw new InvalidTokenError('Invalid token format');
    }

    const { kid } = decoded.header;
    const secret = await this.getSecretByKid(kid);

    if (!secret) {
      throw new InvalidTokenError('Invalid key ID');
    }

    return jwt.verify(token, secret, {
      algorithms: ['HS256']
    });
  }

  private async getCurrentSecret(): Promise<string> {
    return this.getSecretByKid(this.currentKeyId);
  }

  private async getSecretByKid(kid: string): Promise<string> {
    const secret = await redis.get(`jwt:key:${kid}`);
    
    if (!secret) {
      throw new Error(`JWT key ${kid} not found`);
    }
    
    return secret;
  }

  // Token binding (DPoP - Draft Proof of Possession)
  async createDPoPToken(
    payload: JwtPayload,
    publicKeyThumbprint: string
  ): Promise<string> {
    const dPoPPayload = {
      ...payload,
      cnf: {
        jkt: publicKeyThumbprint // JWK Thumbprint
      }
    };

    return this.signWithKeyRotation(dPoPPayload, {
      expiresIn: '15m'
    });
  }

  // Token introspection endpoint
  async introspectToken(token: string): Promise<TokenIntrospection> {
    try {
      const payload = await this.verifyWithKeyRotation(token);
      
      return {
        active: true,
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        scope: payload.scope,
        client_id: payload.client_id,
        token_type: 'access_token'
      };
    } catch {
      return {
        active: false
      };
    }
  }
}
```

## Access Token + Refresh Token

### 🔄 Token Flow Architecture

```typescript
// types/token.types.ts
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshTokenExpiresIn: number;
}

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  tokenHash: string;
  deviceInfo?: DeviceInfo;
  ipAddress?: string;
  userAgent?: string;
  issuedAt: Date;
  expiresAt: Date;
  revoked: boolean;
  revokedAt?: Date;
  replacedByTokenId?: string;
  lastUsedAt?: Date;
}

export interface DeviceInfo {
  type: 'web' | 'mobile' | 'desktop' | 'tablet';
  os?: string;
  browser?: string;
  deviceId?: string;
}
```

### 🏗️ Token Service Implementation

```typescript
// services/token.service.ts
import { randomBytes, createHash } from 'crypto';
import { addDays, isBefore } from 'date-fns';
import { TokenPair, RefreshTokenRecord } from '@/types/token.types';

export class TokenService {
  private readonly refreshTokenExpiryDays = 7;
  private readonly maxActiveSessions = 5;

  constructor(
    private jwtService: JwtService,
    private refreshTokenRepository: RefreshTokenRepository
  ) {}

  // Generate token pair with refresh token storage
  async generateTokenPair(user: User, context: {
    ipAddress?: string;
    userAgent?: string;
    deviceInfo?: DeviceInfo;
  }): Promise<TokenPair> {
    // Generate tokens
    const accessToken = await this.jwtService.createAccessToken({
      sub: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions
    });

    const refreshToken = await this.jwtService.createRefreshToken(user.id);
    const refreshTokenHash = this.hashToken(refreshToken);

    // Enforce session limits
    await this.enforceSessionLimits(user.id);

    // Store refresh token
    const refreshTokenRecord: Partial<RefreshTokenRecord> = {
      userId: user.id,
      tokenHash: refreshTokenHash,
      deviceInfo: context.deviceInfo,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      issuedAt: new Date(),
      expiresAt: addDays(new Date(), this.refreshTokenExpiryDays),
      revoked: false
    };

    await this.refreshTokenRepository.create(refreshTokenRecord as RefreshTokenRecord);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: 15 * 60, // 15 minutes
      refreshTokenExpiresIn: this.refreshTokenExpiryDays * 24 * 60 * 60
    };
  }

  // Refresh access token
  async refreshAccessToken(
    refreshToken: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
    }
  ): Promise<TokenPair> {
    // Verify refresh token
    const { sub: userId, jti } = await this.jwtService.verifyRefreshToken(refreshToken);
    const refreshTokenHash = this.hashToken(refreshToken);

    // Find refresh token in database
    const tokenRecord = await this.refreshTokenRepository.findByHash(refreshTokenHash);

    if (!tokenRecord) {
      throw new InvalidTokenError('Refresh token not found');
    }

    if (tokenRecord.revoked) {
      throw new TokenRevokedError('Refresh token has been revoked');
    }

    if (tokenRecord.userId !== userId) {
      throw new SecurityViolationError('Token user mismatch');
    }

    if (isBefore(tokenRecord.expiresAt, new Date())) {
      throw new TokenExpiredError('Refresh token expired');
    }

    // Check for suspicious activity
    if (context.ipAddress && tokenRecord.ipAddress !== context.ipAddress) {
      await this.logSuspiciousActivity({
        userId,
        tokenId: tokenRecord.id,
        oldIp: tokenRecord.ipAddress,
        newIp: context.ipAddress,
        type: 'ip_mismatch'
      });
    }

    // Update last used timestamp
    tokenRecord.lastUsedAt = new Date();
    await this.refreshTokenRepository.update(tokenRecord.id, {
      lastUsedAt: tokenRecord.lastUsedAt
    });

    // Get user data
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UserNotFoundError('User not found');
    }

    // Generate new token pair with rotation
    const newTokenPair = await this.generateTokenPair(user, {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      deviceInfo: tokenRecord.deviceInfo
    });

    // Revoke old refresh token (optional: implement refresh token rotation)
    await this.revokeRefreshToken(tokenRecord.id);

    return newTokenPair;
  }

  // Revoke refresh token
  async revokeRefreshToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepository.update(tokenId, {
      revoked: true,
      revokedAt: new Date()
    });
  }

  // Revoke all refresh tokens for user
  async revokeAllUserTokens(userId: string, excludeTokenId?: string): Promise<void> {
    const tokens = await this.refreshTokenRepository.findActiveByUser(userId);

    for (const token of tokens) {
      if (excludeTokenId && token.id === excludeTokenId) {
        continue;
      }
      await this.revokeRefreshToken(token.id);
    }

    // Send security notification
    await this.notificationService.sendSecurityNotification(userId, {
      type: 'all_sessions_revoked',
      timestamp: new Date()
    });
  }

  // Hash token for storage (prevents plaintext token storage)
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  // Enforce session limits
  private async enforceSessionLimits(userId: string): Promise<void> {
    const activeSessions = await this.refreshTokenRepository.countActiveByUser(userId);

    if (activeSessions >= this.maxActiveSessions) {
      // Revoke oldest sessions
      const oldestSessions = await this.refreshTokenRepository.findOldestByUser(
        userId,
        activeSessions - this.maxActiveSessions + 1
      );

      for (const session of oldestSessions) {
        await this.revokeRefreshToken(session.id);
      }

      // Notify user
      await this.notificationService.sendSecurityNotification(userId, {
        type: 'session_limit_exceeded',
        maxSessions: this.maxActiveSessions
      });
    }
  }

  // Get active sessions for user
  async getUserSessions(userId: string): Promise<SessionInfo[]> {
    const tokens = await this.refreshTokenRepository.findActiveByUser(userId);

    return tokens.map(token => ({
      id: token.id,
      device: token.deviceInfo,
      ipAddress: token.ipAddress,
      userAgent: token.userAgent,
      issuedAt: token.issuedAt,
      lastUsedAt: token.lastUsedAt,
      expiresAt: token.expiresAt
    }));
  }
}
```

### 🚀 Token Management API

```typescript
// controllers/auth.controller.ts
import { Request, Response, NextFunction } from 'express';
import { TokenService } from '@/services/token.service';
import { DeviceDetector } from '@/utils/device-detector';

export class AuthController {
  constructor(
    private tokenService: TokenService,
    private deviceDetector: DeviceDetector
  ) {}

  // Login endpoint
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password, deviceId } = req.body;

      // Authenticate user
      const user = await this.authService.authenticate(email, password);

      // Detect device information
      const deviceInfo = this.deviceDetector.detect(req);

      // Generate token pair
      const tokens = await this.tokenService.generateTokenPair(user, {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        deviceInfo: {
          ...deviceInfo,
          deviceId
        }
      });

      // Set refresh token in HTTP-only cookie
      res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: tokens.refreshTokenExpiresIn * 1000,
        path: '/api/auth/refresh'
      });

      // Return access token in response body
      res.json({
        accessToken: tokens.accessToken,
        tokenType: tokens.tokenType,
        expiresIn: tokens.expiresIn,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          permissions: user.permissions
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // Refresh token endpoint
  async refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const refreshToken = req.cookies.refresh_token || req.body.refreshToken;

      if (!refreshToken) {
        throw new InvalidTokenError('Refresh token required');
      }

      const tokens = await this.tokenService.refreshAccessToken(refreshToken, {
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });

      // Update refresh token cookie
      res.cookie('refresh_token', tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: tokens.refreshTokenExpiresIn * 1000,
        path: '/api/auth/refresh'
      });

      res.json({
        accessToken: tokens.accessToken,
        tokenType: tokens.tokenType,
        expiresIn: tokens.expiresIn
      });
    } catch (error) {
      next(error);
    }
  }

  // Logout endpoint
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const refreshToken = req.cookies.refresh_token;

      if (refreshToken) {
        // Revoke the refresh token
        const tokenHash = createHash('sha256').update(refreshToken).digest('hex');
        const tokenRecord = await this.refreshTokenRepository.findByHash(tokenHash);
        
        if (tokenRecord) {
          await this.tokenService.revokeRefreshToken(tokenRecord.id);
        }

        // Clear the cookie
        res.clearCookie('refresh_token', {
          path: '/api/auth/refresh'
        });
      }

      // If access token is provided, add to blacklist
      const authHeader = req.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        const accessToken = authHeader.substring(7);
        await this.tokenBlacklistService.add(accessToken, 15 * 60); // Blacklist for 15 minutes
      }

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      next(error);
    }
  }

  // Get active sessions
  async getSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.sub;
      const sessions = await this.tokenService.getUserSessions(userId);

      res.json({ sessions });
    } catch (error) {
      next(error);
    }
  }

  // Revoke specific session
  async revokeSession(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { sessionId } = req.params;
      const userId = req.user!.sub;

      const token = await this.refreshTokenRepository.findById(sessionId);

      if (!token || token.userId !== userId) {
        throw new NotFoundError('Session not found');
      }

      await this.tokenService.revokeRefreshToken(sessionId);

      res.json({ message: 'Session revoked successfully' });
    } catch (error) {
      next(error);
    }
  }
}
```

## Password Hashing

### 🔐 Modern Password Hashing

```typescript
// services/password.service.ts
import * as argon2 from 'argon2';
import * as bcrypt from 'bcrypt';
import { randomBytes, scrypt, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

export enum HashAlgorithm {
  ARGON2ID = 'argon2id',
  BCRYPT = 'bcrypt',
  SCRYPT = 'scrypt'
}

export interface HashOptions {
  algorithm: HashAlgorithm;
  // Common options
  saltLength?: number;
  // Algorithm-specific options
  argon2Options?: Argon2Options;
  bcryptOptions?: BcryptOptions;
  scryptOptions?: ScryptOptions;
}

export interface Argon2Options {
  type?: argon2.argon2d | argon2.argon2i | argon2.argon2id;
  timeCost?: number;
  memoryCost?: number;
  parallelism?: number;
  hashLength?: number;
}

export interface BcryptOptions {
  rounds?: number;
}

export interface ScryptOptions {
  keyLength?: number;
  cost?: number;
  blockSize?: number;
  parallelization?: number;
}

export class PasswordService {
  private readonly defaultOptions: HashOptions = {
    algorithm: HashAlgorithm.ARGON2ID,
    saltLength: 32,
    argon2Options: {
      type: argon2.argon2id,
      timeCost: 3,
      memoryCost: 65536, // 64MB
      parallelism: 4,
      hashLength: 32
    },
    bcryptOptions: {
      rounds: 12
    },
    scryptOptions: {
      keyLength: 32,
      cost: 16384,
      blockSize: 8,
      parallelization: 1
    }
  };

  // Generate salt
  private generateSalt(length: number = 32): string {
    return randomBytes(length).toString('hex');
  }

  // Hash password with specified algorithm
  async hashPassword(
    password: string,
    options: Partial<HashOptions> = {}
  ): Promise<{ hash: string; salt: string; algorithm: HashAlgorithm }> {
    const config = { ...this.defaultOptions, ...options };
    const salt = this.generateSalt(config.saltLength);

    let hash: string;

    switch (config.algorithm) {
      case HashAlgorithm.ARGON2ID:
        hash = await this.hashWithArgon2(password, salt, config.argon2Options!);
        break;
      
      case HashAlgorithm.BCRYPT:
        hash = await this.hashWithBcrypt(password, salt, config.bcryptOptions!);
        break;
      
      case HashAlgorithm.SCRYPT:
        hash = await this.hashWithScrypt(password, salt, config.scryptOptions!);
        break;
      
      default:
        throw new Error(`Unsupported algorithm: ${config.algorithm}`);
    }

    // Store algorithm and salt with hash for verification
    const encodedHash = this.encodeHash(hash, salt, config.algorithm);

    return {
      hash: encodedHash,
      salt,
      algorithm: config.algorithm
    };
  }

  // Verify password
  async verifyPassword(
    password: string,
    encodedHash: string
  ): Promise<boolean> {
    const { hash, salt, algorithm } = this.decodeHash(encodedHash);

    switch (algorithm) {
      case HashAlgorithm.ARGON2ID:
        return this.verifyWithArgon2(password, hash, salt);
      
      case HashAlgorithm.BCRYPT:
        return this.verifyWithBcrypt(password, hash, salt);
      
      case HashAlgorithm.SCRYPT:
        return this.verifyWithScrypt(password, hash, salt);
      
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  // Check if password needs rehashing (for algorithm upgrades)
  async needsRehash(encodedHash: string): Promise<boolean> {
    const { algorithm } = this.decodeHash(encodedHash);
    
    // Check if using old algorithm or weak parameters
    if (algorithm !== this.defaultOptions.algorithm) {
      return true;
    }

    // Check for weak parameters
    const { hash, salt } = this.decodeHash(encodedHash);
    
    switch (algorithm) {
      case HashAlgorithm.ARGON2ID:
        const argon2Info = await argon2.verify(hash, 'dummy');
        // Check if parameters match current standards
        return argon2Info.needsRehash;
      
      case HashAlgorithm.BCRYPT:
        const bcryptRounds = parseInt(hash.split('$')[2]);
        return bcryptRounds < this.defaultOptions.bcryptOptions!.rounds!;
      
      default:
        return false;
    }
  }

  // Generate secure random password
  generateSecurePassword(length: number = 16): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const randomValues = randomBytes(length);
    let password = '';

    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }

    // Ensure password contains at least one of each required character type
    if (!/[a-z]/.test(password)) {
      password = password.slice(0, -1) + 'a';
    }
    if (!/[A-Z]/.test(password)) {
      password = password.slice(0, -1) + 'A';
    }
    if (!/[0-9]/.test(password)) {
      password = password.slice(0, -1) + '1';
    }
    if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
      password = password.slice(0, -1) + '!';
    }

    return password;
  }

  // Password strength checker
  checkPasswordStrength(password: string): {
    score: number;
    feedback: string[];
    meetsRequirements: boolean;
  } {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    else feedback.push('Password should be at least 8 characters long');

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');
    
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');
    
    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Add numbers');
    
    if (/[^a-zA-Z0-9]/.test(password)) score += 1;
    else feedback.push('Add special characters');

    // Common password check
    const commonPasswords = ['password', '123456', 'qwerty', 'letmein'];
    if (commonPasswords.includes(password.toLowerCase())) {
      score = 0;
      feedback.push('Password is too common');
    }

    // Sequential characters check
    if (/(.)\1{2,}/.test(password)) {
      score -= 1;
      feedback.push('Avoid repeating characters');
    }

    return {
      score: Math.max(0, Math.min(5, score)),
      feedback,
      meetsRequirements: score >= 3
    };
  }

  // Private methods for specific algorithms
  private async hashWithArgon2(
    password: string,
    salt: string,
    options: Argon2Options
  ): Promise<string> {
    return argon2.hash(password, {
      ...options,
      salt: Buffer.from(salt, 'hex'),
      raw: false
    });
  }

  private async hashWithBcrypt(
    password: string,
    salt: string,
    options: BcryptOptions
  ): Promise<string> {
    // BCrypt generates its own salt internally
    return bcrypt.hash(password, options.rounds);
  }

  private async hashWithScrypt(
    password: string,
    salt: string,
    options: ScryptOptions
  ): Promise<string> {
    const derivedKey = await scryptAsync(
      password,
      salt,
      options.keyLength!,
      {
        N: options.cost!,
        r: options.blockSize!,
        p: options.parallelization!
      }
    ) as Buffer;

    return derivedKey.toString('hex');
  }

  private async verifyWithArgon2(
    password: string,
    hash: string,
    salt: string
  ): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  private async verifyWithBcrypt(
    password: string,
    hash: string,
    salt: string
  ): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch {
      return false;
    }
  }

  private async verifyWithScrypt(
    password: string,
    hash: string,
    salt: string
  ): Promise<boolean> {
    try {
      const derivedKey = await scryptAsync(
        password,
        salt,
        Buffer.from(hash, 'hex').length,
        {
          N: 16384,
          r: 8,
          p: 1
        }
      ) as Buffer;

      const hashBuffer = Buffer.from(hash, 'hex');
      return timingSafeEqual(derivedKey, hashBuffer);
    } catch {
      return false;
    }
  }

  // Encode hash for storage
  private encodeHash(hash: string, salt: string, algorithm: HashAlgorithm): string {
    return `$${algorithm}$${salt}$${hash}`;
  }

  // Decode hash from storage
  private decodeHash(encodedHash: string): {
    hash: string;
    salt: string;
    algorithm: HashAlgorithm;
  } {
    const parts = encodedHash.split('$').filter(Boolean);
    
    if (parts.length !== 3) {
      throw new Error('Invalid hash format');
    }

    const [algorithm, salt, hash] = parts;

    if (!Object.values(HashAlgorithm).includes(algorithm as HashAlgorithm)) {
      throw new Error(`Unknown algorithm: ${algorithm}`);
    }

    return {
      hash,
      salt,
      algorithm: algorithm as HashAlgorithm
    };
  }
}
```

### 🔄 Password Policy Enforcement

```typescript
// services/password-policy.service.ts
import { PasswordService } from './password.service';
import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

export class PasswordPolicyService {
  private readonly passwordHistorySize = 5;
  private readonly maxFailedAttempts = 5;
  private readonly lockoutDuration = 15 * 60 * 1000; // 15 minutes

  constructor(
    private passwordService: PasswordService,
    private userRepository: UserRepository,
    private passwordHistoryRepository: PasswordHistoryRepository
  ) {
    // Configure zxcvbn
    const options = {
      dictionary: {
        ...zxcvbnCommonPackage.dictionary,
        ...zxcvbnEnPackage.dictionary,
      },
      graphs: zxcvbnCommonPackage.adjacencyGraphs,
      useLevenshteinDistance: true,
    };
    zxcvbnOptions.setOptions(options);
  }

  // Validate password against policy
  async validatePassword(
    userId: string,
    newPassword: string,
    currentPassword?: string
  ): Promise<{
    isValid: boolean;
    errors: string[];
    warnings: string[];
    score: number;
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check if same as current password
    if (currentPassword && newPassword === currentPassword) {
      errors.push('New password must be different from current password');
    }

    // Check password strength
    const strength = this.passwordService.checkPasswordStrength(newPassword);
    
    if (!strength.meetsRequirements) {
      errors.push(...strength.feedback);
    }

    // Check against password history
    const isInHistory = await this.isPasswordInHistory(userId, newPassword);
    if (isInHistory) {
      errors.push('Password has been used recently. Please choose a different one.');
    }

    // ZXCVBN advanced analysis
    const zxcvbnResult = zxcvbn(newPassword);
    
    if (zxcvbnResult.score < 3) {
      warnings.push('Password is weak according to advanced analysis');
      
      if (zxcvbnResult.feedback.warning) {
        warnings.push(zxcvbnResult.feedback.warning);
      }
      
      if (zxcvbnResult.feedback.suggestions.length > 0) {
        warnings.push(...zxcvbnResult.feedback.suggestions);
      }
    }

    // Check for common patterns
    if (this.hasCommonPattern(newPassword)) {
      warnings.push('Password contains common patterns that are easy to guess');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      score: zxcvbnResult.score
    };
  }

  // Check if password is in history
  private async isPasswordInHistory(userId: string, password: string): Promise<boolean> {
    const history = await this.passwordHistoryRepository.getRecentPasswords(
      userId,
      this.passwordHistorySize
    );

    for (const oldHash of history) {
      const isValid = await this.passwordService.verifyPassword(password, oldHash);
      if (isValid) {
        return true;
      }
    }

    return false;
  }

  // Update password with policy enforcement
  async updatePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    // Verify current password
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UserNotFoundError('User not found');
    }

    const isCurrentValid = await this.passwordService.verifyPassword(
      currentPassword,
      user.passwordHash
    );

    if (!isCurrentValid) {
      await this.recordFailedAttempt(userId);
      throw new InvalidCredentialsError('Current password is incorrect');
    }

    // Validate new password
    const validation = await this.validatePassword(
      userId,
      newPassword,
      currentPassword
    );

    if (!validation.isValid) {
      throw new PasswordPolicyError('Password does not meet policy requirements', {
        errors: validation.errors,
        warnings: validation.warnings
      });
    }

    // Hash new password
    const { hash: newHash } = await this.passwordService.hashPassword(newPassword);

    // Update user password
    await this.userRepository.updatePassword(userId, newHash);

    // Add to password history
    await this.passwordHistoryRepository.addPassword(userId, newHash);

    // Reset failed attempts
    await this.resetFailedAttempts(userId);

    // Send notification
    await this.notificationService.sendPasswordChangedNotification(userId);
  }

  // Handle failed login attempts
  async recordFailedAttempt(userId: string): Promise<void> {
    const attempts = await this.userRepository.incrementFailedAttempts(userId);
    
    if (attempts >= this.maxFailedAttempts) {
      await this.lockAccount(userId);
    }
  }

  // Lock account temporarily
  private async lockAccount(userId: string): Promise<void> {
    const lockoutUntil = new Date(Date.now() + this.lockoutDuration);
    
    await this.userRepository.lockAccount(userId, lockoutUntil);
    
    // Send security alert
    await this.notificationService.sendAccountLockedNotification(userId, {
      lockoutUntil,
      reason: 'too_many_failed_attempts'
    });
  }

  // Check if account is locked
  async isAccountLocked(userId: string): Promise<boolean> {
    const user = await this.userRepository.findById(userId);
    
    if (!user) {
      return false;
    }

    if (!user.lockedUntil) {
      return false;
    }

    return new Date() < user.lockedUntil;
  }

  // Reset failed attempts
  async resetFailedAttempts(userId: string): Promise<void> {
    await this.userRepository.resetFailedAttempts(userId);
  }

  // Check for common patterns
  private hasCommonPattern(password: string): boolean {
    const patterns = [
      /^123/, /^qwerty/, /^password/, /^admin/, /^welcome/,
      /^\d{6,}$/, // Only numbers
      /^[a-zA-Z]{6,}$/, // Only letters
      /(.)\1{3,}/, // Repeated characters
      /(abc|def|ghi|jkl|mno|pqr|stu|vwx|yz)/i, // Keyboard sequences
      /(\d)\1{2,}/, // Repeated numbers
    ];

    return patterns.some(pattern => pattern.test(password));
  }

  // Generate password expiration policy
  async getPasswordExpirationInfo(userId: string): Promise<{
    expiresIn: number | null;
    requiresChange: boolean;
    lastChanged: Date;
  }> {
    const passwordAge = await this.passwordHistoryRepository.getPasswordAge(userId);
    const passwordExpiryDays = 90; // 90 days policy

    if (!passwordAge) {
      return {
        expiresIn: null,
        requiresChange: false,
        lastChanged: new Date()
      };
    }

    const ageInDays = (Date.now() - passwordAge.getTime()) / (1000 * 60 * 60 * 24);
    const expiresIn = Math.max(0, passwordExpiryDays - ageInDays);
    const requiresChange = expiresIn <= 7; // Require change if expires in 7 days or less

    return {
      expiresIn: Math.ceil(expiresIn),
      requiresChange,
      lastChanged: passwordAge
    };
  }
}
```

## Session Authentication

### 🍪 Session-Based Authentication

```typescript
// services/session.service.ts
import { randomBytes, createHash } from 'crypto';
import Redis from 'ioredis';
import { addMinutes, isAfter } from 'date-fns';

export interface SessionData {
  userId: string;
  email: string;
  role: string;
  permissions: string[];
  createdAt: Date;
  lastAccessedAt: Date;
  userAgent?: string;
  ipAddress?: string;
  deviceInfo?: DeviceInfo;
  metadata?: Record<string, any>;
}

export interface SessionConfig {
  ttl: number; // Session TTL in seconds
  idleTimeout: number; // Idle timeout in seconds
  renewOnAccess: boolean;
  cookieName: string;
  secureCookies: boolean;
}

export class SessionService {
  private readonly redis: Redis;
  private readonly config: SessionConfig;

  constructor(redis: Redis, config: Partial<SessionConfig> = {}) {
    this.redis = redis;
    this.config = {
      ttl: 24 * 60 * 60, // 24 hours
      idleTimeout: 30 * 60, // 30 minutes
      renewOnAccess: true,
      cookieName: 'session_id',
      secureCookies: process.env.NODE_ENV === 'production',
      ...config
    };
  }

  // Create new session
  async createSession(user: User, context: {
    userAgent?: string;
    ipAddress?: string;
    deviceInfo?: DeviceInfo;
  }): Promise<{ sessionId: string; cookieConfig: CookieOptions }> {
    const sessionId = this.generateSessionId();
    const sessionKey = this.getSessionKey(sessionId);

    const sessionData: SessionData = {
      userId: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions,
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      deviceInfo: context.deviceInfo,
      metadata: {}
    };

    // Store session in Redis
    await this.redis.setex(
      sessionKey,
      this.config.ttl,
      JSON.stringify(sessionData)
    );

    // Store session ID in user's session set
    const userSessionsKey = `user:sessions:${user.id}`;
    await this.redis.sadd(userSessionsKey, sessionId);
    await this.redis.expire(userSessionsKey, this.config.ttl);

    return {
      sessionId,
      cookieConfig: this.getCookieConfig(sessionId)
    };
  }

  // Get session data
  async getSession(sessionId: string): Promise<SessionData | null> {
    const sessionKey = this.getSessionKey(sessionId);
    const sessionData = await this.redis.get(sessionKey);

    if (!sessionData) {
      return null;
    }

    const parsedData = JSON.parse(sessionData) as SessionData;

    // Check idle timeout
    if (this.config.idleTimeout > 0) {
      const lastAccessed = new Date(parsedData.lastAccessedAt);
      const idleTimeout = addMinutes(lastAccessed, this.config.idleTimeout / 60);

      if (isAfter(new Date(), idleTimeout)) {
        await this.destroySession(sessionId);
        return null;
      }
    }

    // Update last accessed time if renewOnAccess is enabled
    if (this.config.renewOnAccess) {
      parsedData.lastAccessedAt = new Date();
      await this.redis.setex(
        sessionKey,
        this.config.ttl,
        JSON.stringify(parsedData)
      );
    }

    return parsedData;
  }

  // Update session data
  async updateSession(
    sessionId: string,
    updates: Partial<SessionData>
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      throw new SessionNotFoundError('Session not found');
    }

    const updatedSession = { ...session, ...updates };
    const sessionKey = this.getSessionKey(sessionId);

    await this.redis.setex(
      sessionKey,
      this.config.ttl,
      JSON.stringify(updatedSession)
    );
  }

  // Destroy session
  async destroySession(sessionId: string): Promise<void> {
    const sessionKey = this.getSessionKey(sessionId);
    
    // Get user ID before deleting
    const sessionData = await this.redis.get(sessionKey);
    
    if (sessionData) {
      const parsedData = JSON.parse(sessionData) as SessionData;
      const userSessionsKey = `user:sessions:${parsedData.userId}`;
      
      // Remove from user's session set
      await this.redis.srem(userSessionsKey, sessionId);
    }

    // Delete session
    await this.redis.del(sessionKey);
  }

  // Destroy all sessions for user
  async destroyAllUserSessions(userId: string, excludeSessionId?: string): Promise<void> {
    const userSessionsKey = `user:sessions:${userId}`;
    const sessionIds = await this.redis.smembers(userSessionsKey);

    for (const sessionId of sessionIds) {
      if (sessionId === excludeSessionId) {
        continue;
      }

      const sessionKey = this.getSessionKey(sessionId);
      await this.redis.del(sessionKey);
    }

    // Clear the set
    await this.redis.del(userSessionsKey);
  }

  // Get all active sessions for user
  async getUserSessions(userId: string): Promise<SessionInfo[]> {
    const userSessionsKey = `user:sessions:${userId}`;
    const sessionIds = await this.redis.smembers(userSessionsKey);
    const sessions: SessionInfo[] = [];

    for (const sessionId of sessionIds) {
      const sessionData = await this.getSession(sessionId);
      
      if (sessionData) {
        sessions.push({
          sessionId,
          deviceInfo: sessionData.deviceInfo,
          ipAddress: sessionData.ipAddress,
          userAgent: sessionData.userAgent,
          createdAt: sessionData.createdAt,
          lastAccessedAt: sessionData.lastAccessedAt
        });
      }
    }

    return sessions;
  }

  // Regenerate session (session fixation protection)
  async regenerateSession(oldSessionId: string): Promise<string> {
    const oldSession = await this.getSession(oldSessionId);
    
    if (!oldSession) {
      throw new SessionNotFoundError('Session not found');
    }

    // Create new session with same data
    const { sessionId: newSessionId } = await this.createSession(
      {
        id: oldSession.userId,
        email: oldSession.email,
        role: oldSession.role,
        permissions: oldSession.permissions
      } as User,
      {
        userAgent: oldSession.userAgent,
        ipAddress: oldSession.ipAddress,
        deviceInfo: oldSession.deviceInfo
      }
    );

    // Destroy old session
    await this.destroySession(oldSessionId);

    return newSessionId;
  }

  // Generate secure session ID
  private generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  // Get Redis key for session
  private getSessionKey(sessionId: string): string {
    return `session:${sessionId}`;
  }

  // Get cookie configuration
  private getCookieConfig(sessionId: string): CookieOptions {
    return {
      httpOnly: true,
      secure: this.config.secureCookies,
      sameSite: 'strict',
      maxAge: this.config.ttl * 1000,
      path: '/',
      domain: process.env.COOKIE_DOMAIN,
      // Additional security headers
      ...(this.config.secureCookies && {
        partitioned: true, // CHIPS: partitioned cookies
        priority: 'high'
      })
    };
  }

  // Session middleware
  getSessionMiddleware(): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      const sessionId = req.cookies[this.config.cookieName];

      if (!sessionId) {
        return next();
      }

      try {
        const sessionData = await this.getSession(sessionId);

        if (sessionData) {
          // Attach session data to request
          req.session = sessionData;
          req.sessionId = sessionId;

          // Update session TTL on activity
          if (this.config.renewOnAccess) {
            const cookieConfig = this.getCookieConfig(sessionId);
            res.cookie(this.config.cookieName, sessionId, cookieConfig);
          }
        } else {
          // Clear invalid session cookie
          res.clearCookie(this.config.cookieName);
        }
      } catch (error) {
        console.error('Session middleware error:', error);
        res.clearCookie(this.config.cookieName);
      }

      next();
    };
  }
}
```

### 🔒 Session Security Enhancements

```typescript
// services/session-security.service.ts
import { SessionService, SessionData } from './session.service';
import { Request, Response } from 'express';

export class SessionSecurityService {
  constructor(
    private sessionService: SessionService,
    private auditLogger: AuditLogger
  ) {}

  // Enhanced session creation with security checks
  async createSecureSession(
    user: User,
    context: {
      req: Request;
      res: Response;
      deviceInfo?: DeviceInfo;
    }
  ): Promise<void> {
    const { req, res } = context;

    // Check for suspicious activity
    await this.checkSuspiciousActivity(user.id, {
      ipAddress: req.ip,
      userAgent: req.get('user-agent')
    });

    // Create session
    const { sessionId, cookieConfig } = await this.sessionService.createSession(
      user,
      {
        userAgent: req.get('user-agent'),
        ipAddress: req.ip,
        deviceInfo: context.deviceInfo
      }
    );

    // Set secure cookie
    res.cookie(this.sessionService.cookieName, sessionId, cookieConfig);

    // Set additional security headers
    this.setSecurityHeaders(res);

    // Log session creation
    await this.auditLogger.log({
      userId: user.id,
      action: 'session_created',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      sessionId,
      timestamp: new Date()
    });
  }

  // Validate session with additional security checks
  async validateSession(sessionId: string, req: Request): Promise<{
    isValid: boolean;
    sessionData?: SessionData;
    securityFlags: string[];
  }> {
    const sessionData = await this.sessionService.getSession(sessionId);

    if (!sessionData) {
      return {
        isValid: false,
        securityFlags: ['session_not_found']
      };
    }

    const securityFlags: string[] = [];

    // Check IP address change
    if (sessionData.ipAddress && sessionData.ipAddress !== req.ip) {
      securityFlags.push('ip_address_changed');
      
      // Log suspicious activity
      await this.auditLogger.log({
        userId: sessionData.userId,
        action: 'suspicious_session_activity',
        ipAddress: req.ip,
        previousIp: sessionData.ipAddress,
        sessionId,
        timestamp: new Date()
      });
    }

    // Check user agent change
    const currentUserAgent = req.get('user-agent');
    if (sessionData.userAgent && sessionData.userAgent !== currentUserAgent) {
      securityFlags.push('user_agent_changed');
    }

    // Check for session hijacking patterns
    if (await this.isSuspiciousPattern(sessionId, req)) {
      securityFlags.push('suspicious_pattern_detected');
      await this.sessionService.destroySession(sessionId);
      
      return {
        isValid: false,
        securityFlags
      };
    }

    return {
      isValid: true,
      sessionData,
      securityFlags
    };
  }

  // Implement session binding to device
  async bindSessionToDevice(
    sessionId: string,
    deviceFingerprint: string
  ): Promise<void> {
    const session = await this.sessionService.getSession(sessionId);
    
    if (!session) {
      throw new SessionNotFoundError('Session not found');
    }

    // Store device fingerprint in session metadata
    await this.sessionService.updateSession(sessionId, {
      metadata: {
        ...session.metadata,
        deviceFingerprint,
        deviceBoundAt: new Date()
      }
    });
  }

  // Check if session matches device fingerprint
  async verifyDeviceBinding(
    sessionId: string,
    deviceFingerprint: string
  ): Promise<boolean> {
    const session = await this.sessionService.getSession(sessionId);
    
    if (!session) {
      return false;
    }

    const storedFingerprint = session.metadata?.deviceFingerprint;
    
    if (!storedFingerprint) {
      // Device binding not required for this session
      return true;
    }

    return storedFingerprint === deviceFingerprint;
  }

  // Implement session nonce for CSRF protection
  async generateSessionNonce(sessionId: string): Promise<string> {
    const nonce = randomBytes(16).toString('hex');
    const nonceHash = createHash('sha256').update(nonce).digest('hex');

    const session = await this.sessionService.getSession(sessionId);
    
    if (session) {
      await this.sessionService.updateSession(sessionId, {
        metadata: {
          ...session.metadata,
          csrfNonce: nonceHash
        }
      });
    }

    return nonce;
  }

  // Verify CSRF nonce
  async verifyCsrfNonce(
    sessionId: string,
    nonce: string
  ): Promise<boolean> {
    const session = await this.sessionService.getSession(sessionId);
    
    if (!session) {
      return false;
    }

    const storedNonceHash = session.metadata?.csrfNonce;
    
    if (!storedNonceHash) {
      return false;
    }

    const nonceHash = createHash('sha256').update(nonce).digest('hex');
    const isValid = timingSafeEqual(
      Buffer.from(nonceHash, 'hex'),
      Buffer.from(storedNonceHash, 'hex')
    );

    // Clear nonce after use (one-time use)
    if (isValid) {
      await this.sessionService.updateSession(sessionId, {
        metadata: {
          ...session.metadata,
          csrfNonce: undefined
        }
      });
    }

    return isValid;
  }

  // Rate limiting per session
  async checkSessionRateLimit(
    sessionId: string,
    action: string,
    limit: number,
    windowMs: number
  ): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }> {
    const key = `rate_limit:session:${sessionId}:${action}`;
    const current = await this.redis.get(key);

    if (!current) {
      await this.redis.setex(key, windowMs / 1000, '1');
      return {
        allowed: true,
        remaining: limit - 1,
        resetTime: Date.now() + windowMs
      };
    }

    const count = parseInt(current, 10);
    
    if (count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: Date.now() + (await this.redis.ttl(key)) * 1000
      };
    }

    await this.redis.incr(key);
    return {
      allowed: true,
      remaining: limit - count - 1,
      resetTime: Date.now() + (await this.redis.ttl(key)) * 1000
    };
  }

  private async checkSuspiciousActivity(
    userId: string,
    context: { ipAddress?: string; userAgent?: string }
  ): Promise<void> {
    // Implement suspicious activity detection
    const recentLogins = await this.auditLogger.getRecentLogins(userId, 10);
    
    // Check for multiple locations in short time
    const uniqueIps = new Set(recentLogins.map(login => login.ipAddress));
    
    if (uniqueIps.size > 3) {
      await this.notificationService.sendSecurityAlert(userId, {
        type: 'multiple_locations',
        locations: Array.from(uniqueIps)
      });
    }
  }

  private async isSuspiciousPattern(
    sessionId: string,
    req: Request
  ): Promise<boolean> {
    // Implement pattern detection for session hijacking
    // Check request frequency, headers, etc.
    return false;
  }

  private setSecurityHeaders(res: Response): void {
    // Set security headers for session protection
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    // Content Security Policy
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline'"
    );
  }
}
```

## OAuth 2.0 & OpenID Connect

### 🔗 OAuth 2.0 Implementation

```typescript
// types/oauth.types.ts
export enum OAuthGrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  IMPLICIT = 'implicit',
  PASSWORD = 'password',
  CLIENT_CREDENTIALS = 'client_credentials',
  REFRESH_TOKEN = 'refresh_token',
  DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
}

export enum OAuthResponseType {
  CODE = 'code',
  TOKEN = 'token'
}

export interface OAuthClient {
  id: string;
  secret: string;
  name: string;
  redirectUris: string[];
  grants: OAuthGrantType[];
  scopes: string[];
  accessTokenLifetime: number;
  refreshTokenLifetime: number;
  confidential: boolean;
  trusted: boolean;
}

export interface AuthorizationRequest {
  responseType: OAuthResponseType;
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'plain' | 'S256';
  nonce?: string; // For OpenID Connect
}

export interface AuthorizationCode {
  code: string;
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'plain' | 'S256';
  expiresAt: Date;
  used: boolean;
  nonce?: string;
}
```

### 🛠️ OAuth 2.0 Service

```typescript
// services/oauth.service.ts
import { randomBytes, createHash } from 'crypto';
import { addSeconds } from 'date-fns';
import { URL } from 'url';

export class OAuthService {
  private readonly authorizationCodeLifetime = 10 * 60; // 10 minutes
  private readonly pkceRequired = true;

  constructor(
    private clientRepository: OAuthClientRepository,
    private authCodeRepository: AuthorizationCodeRepository,
    private tokenService: TokenService
  ) {}

  // Validate authorization request
  async validateAuthorizationRequest(
    query: Record<string, string>
  ): Promise<{
    valid: boolean;
    client?: OAuthClient;
    error?: string;
    errorDescription?: string;
  }> {
    const {
      response_type: responseType,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      nonce
    } = query;

    // Validate response type
    if (!responseType || !Object.values(OAuthResponseType).includes(responseType as OAuthResponseType)) {
      return {
        valid: false,
        error: 'unsupported_response_type',
        errorDescription: 'Unsupported response type'
      };
    }

    // Validate client
    const client = await this.clientRepository.findById(clientId);
    if (!client) {
      return {
        valid: false,
        error: 'invalid_client',
        errorDescription: 'Invalid client ID'
      };
    }

    // Validate redirect URI
    if (!this.isValidRedirectUri(client, redirectUri)) {
      return {
        valid: false,
        error: 'invalid_request',
        errorDescription: 'Invalid redirect URI'
      };
    }

    // Validate scopes
    if (scope && !this.isValidScope(client, scope)) {
      return {
        valid: false,
        error: 'invalid_scope',
        errorDescription: 'Invalid scope requested'
      };
    }

    // PKCE validation for public clients
    if (!client.confidential && this.pkceRequired) {
      if (!codeChallenge) {
        return {
          valid: false,
          error: 'invalid_request',
          errorDescription: 'PKCE code challenge required'
        };
      }

      if (codeChallengeMethod && !['plain', 'S256'].includes(codeChallengeMethod)) {
        return {
          valid: false,
          error: 'invalid_request',
          errorDescription: 'Invalid code challenge method'
        };
      }
    }

    return {
      valid: true,
      client
    };
  }

  // Create authorization code
  async createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string,
    codeChallenge?: string,
    codeChallengeMethod?: string,
    nonce?: string
  ): Promise<string> {
    const code = randomBytes(32).toString('hex');
    const expiresAt = addSeconds(new Date(), this.authorizationCodeLifetime);

    const authCode: AuthorizationCode = {
      code,
      clientId,
      userId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod: codeChallengeMethod as 'plain' | 'S256',
      expiresAt,
      used: false,
      nonce
    };

    await this.authCodeRepository.save(authCode);

    return code;
  }

  // Exchange authorization code for tokens
  async exchangeCodeForTokens(
    code: string,
    clientId: string,
    clientSecret: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    tokenType: string;
    expiresIn: number;
    scope: string;
    idToken?: string; // For OpenID Connect
  }> {
    // Validate client credentials
    const client = await this.clientRepository.findById(clientId);
    
    if (!client || client.secret !== clientSecret) {
      throw new InvalidClientError('Invalid client credentials');
    }

    // Get authorization code
    const authCode = await this.authCodeRepository.findByCode(code);
    
    if (!authCode) {
      throw new InvalidGrantError('Invalid authorization code');
    }

    // Check if code is expired
    if (new Date() > authCode.expiresAt) {
      throw new InvalidGrantError('Authorization code expired');
    }

    // Check if code was already used
    if (authCode.used) {
      throw new InvalidGrantError('Authorization code already used');
    }

    // Validate redirect URI
    if (authCode.redirectUri !== redirectUri) {
      throw new InvalidGrantError('Redirect URI mismatch');
    }

    // Validate PKCE code verifier
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        throw new InvalidGrantError('PKCE code verifier required');
      }

      const isValid = this.verifyCodeChallenge(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod || 'plain'
      );

      if (!isValid) {
        throw new InvalidGrantError('Invalid PKCE code verifier');
      }
    }

    // Mark code as used
    await this.authCodeRepository.markAsUsed(code);

    // Get user
    const user = await this.userRepository.findById(authCode.userId);
    if (!user) {
      throw new InvalidGrantError('User not found');
    }

    // Generate tokens
    const tokens = await this.tokenService.generateTokenPair(user, {
      scope: authCode.scope
    });

    // Generate ID token for OpenID Connect
    let idToken: string | undefined;
    if (authCode.nonce) {
      idToken = await this.generateIdToken(user, authCode.nonce, clientId);
    }

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      tokenType: tokens.tokenType,
      expiresIn: tokens.expiresIn,
      scope: authCode.scope,
      idToken
    };
  }

  // Client credentials flow
  async clientCredentialsGrant(
    clientId: string,
    clientSecret: string,
    scope?: string
  ): Promise<{
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    scope: string;
  }> {
    const client = await this.clientRepository.findById(clientId);
    
    if (!client || client.secret !== clientSecret) {
      throw new InvalidClientError('Invalid client credentials');
    }

    if (!client.grants.includes(OAuthGrantType.CLIENT_CREDENTIALS)) {
      throw new UnauthorizedClientError('Client not authorized for this grant type');
    }

    // Validate scope
    const validScope = scope ? this.validateScopeForClient(client, scope) : client.scopes[0];

    // Create access token for client (no user)
    const accessToken = await this.tokenService.createClientAccessToken(
      clientId,
      validScope
    );

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: client.accessTokenLifetime,
      scope: validScope
    };
  }

  // Refresh token grant
  async refreshTokenGrant(
    refreshToken: string,
    clientId: string,
    clientSecret: string,
    scope?: string
  ): Promise<{
    accessToken: string;
    refreshToken?: string;
    tokenType: string;
    expiresIn: number;
    scope: string;
  }> {
    const client = await this.clientRepository.findById(clientId);
    
    if (!client || client.secret !== clientSecret) {
      throw new InvalidClientError('Invalid client credentials');
    }

    if (!client.grants.includes(OAuthGrantType.REFRESH_TOKEN)) {
      throw new UnauthorizedClientError('Client not authorized for this grant type');
    }

    // Verify and use refresh token
    const tokens = await this.tokenService.refreshAccessToken(refreshToken);

    // Scope down if requested
    if (scope) {
      const currentScopes = tokens.scope.split(' ');
      const requestedScopes = scope.split(' ');
      
      const validScopes = requestedScopes.filter(s => currentScopes.includes(s));
      
      if (validScopes.length === 0) {
        throw new InvalidScopeError('Cannot reduce scope below original');
      }

      tokens.scope = validScopes.join(' ');
    }

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      tokenType: tokens.tokenType,
      expiresIn: tokens.expiresIn,
      scope: tokens.scope
    };
  }

  // Token introspection (RFC 7662)
  async introspectToken(
    token: string,
    tokenTypeHint?: 'access_token' | 'refresh_token',
    clientId?: string,
    clientSecret?: string
  ): Promise<TokenIntrospection> {
    // Validate client if provided
    if (clientId && clientSecret) {
      const client = await this.clientRepository.findById(clientId);
      if (!client || client.secret !== clientSecret) {
        throw new InvalidClientError('Invalid client credentials');
      }
    }

    try {
      let payload: any;
      
      if (tokenTypeHint === 'refresh_token' || !tokenTypeHint) {
        try {
          payload = await this.tokenService.verifyRefreshToken(token);
        } catch {
          // Not a refresh token, try as access token
        }
      }
      
      if (!payload && (tokenTypeHint === 'access_token' || !tokenTypeHint)) {
        try {
          payload = await this.tokenService.verifyAccessToken(token);
        } catch {
          // Not a valid token
        }
      }

      if (payload) {
        return {
          active: true,
          scope: payload.scope,
          client_id: payload.client_id,
          username: payload.email,
          token_type: tokenTypeHint || 'access_token',
          exp: payload.exp,
          iat: payload.iat,
          sub: payload.sub,
          aud: payload.aud,
          iss: payload.iss
        };
      }
    } catch {
      // Token is invalid
    }

    return { active: false };
  }

  // Token revocation (RFC 7009)
  async revokeToken(
    token: string,
    tokenTypeHint?: string,
    clientId?: string,
    clientSecret?: string
  ): Promise<void> {
    if (clientId && clientSecret) {
      const client = await this.clientRepository.findById(clientId);
      if (!client || client.secret !== clientSecret) {
        throw new InvalidClientError('Invalid client credentials');
      }
    }

    if (tokenTypeHint === 'refresh_token') {
      await this.tokenService.revokeRefreshTokenByValue(token);
    } else {
      // Try to revoke as access token
      await this.tokenService.blacklistAccessToken(token);
    }
  }

  // Private helper methods
  private isValidRedirectUri(client: OAuthClient, redirectUri?: string): boolean {
    if (!redirectUri) {
      // Use first redirect URI if not provided
      return client.redirectUris.length > 0;
    }

    return client.redirectUris.includes(redirectUri);
  }

  private isValidScope(client: OAuthClient, scope: string): boolean {
    const requestedScopes = scope.split(' ');
    const clientScopes = client.scopes;

    return requestedScopes.every(s => clientScopes.includes(s));
  }

  private validateScopeForClient(client: OAuthClient, scope: string): string {
    const requestedScopes = scope.split(' ');
    const validScopes = requestedScopes.filter(s => client.scopes.includes(s));
    
    if (validScopes.length === 0) {
      throw new InvalidScopeError('No valid scopes requested');
    }

    return validScopes.join(' ');
  }

  private verifyCodeChallenge(
    codeVerifier: string,
    codeChallenge: string,
    method: string
  ): boolean {
    if (method === 'plain') {
      return codeVerifier === codeChallenge;
    }

    if (method === 'S256') {
      const hash = createHash('sha256')
        .update(codeVerifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      return hash === codeChallenge;
    }

    return false;
  }

  private async generateIdToken(
    user: User,
    nonce: string,
    clientId: string
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    const idTokenPayload = {
      iss: process.env.JWT_ISSUER,
      sub: user.id,
      aud: clientId,
      exp: now + 3600, // 1 hour
      iat: now,
      nonce,
      auth_time: now,
      name: user.name,
      email: user.email,
      email_verified: user.emailVerified,
      preferred_username: user.username
    };

    return jwt.sign(idTokenPayload, process.env.JWT_ID_TOKEN_SECRET!, {
      algorithm: 'RS256', // Use asymmetric crypto for ID tokens
      header: {
        alg: 'RS256',
        typ: 'JWT',
        kid: process.env.JWK_KID
      }
    });
  }
}
```

### 🔐 OpenID Connect Implementation

```typescript
// services/oidc.service.ts
import { randomBytes } from 'crypto';
import { JWT } from 'jose';
import { OAuthService } from './oauth.service';

export class OpenIDConnectService {
  private readonly supportedClaims = [
    'sub',
    'name',
    'given_name',
    'family_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'email',
    'email_verified',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'phone_number',
    'phone_number_verified',
    'address',
    'updated_at'
  ];

  private readonly supportedScopes = [
    'openid',
    'profile',
    'email',
    'address',
    'phone',
    'offline_access'
  ];

  constructor(
    private oauthService: OAuthService,
    private jwksService: JwksService
  ) {}

  // Generate OpenID Configuration
  getOpenIDConfiguration(): OpenIDConfiguration {
    const baseUrl = process.env.APP_URL;

    return {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      jwks_uri: `${baseUrl}/oauth/jwks`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      scopes_supported: this.supportedScopes,
      response_types_supported: ['code', 'code id_token', 'id_token', 'token id_token'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      grant_types_supported: [
        'authorization_code',
        'implicit',
        'refresh_token',
        'client_credentials',
        'password'
      ],
      subject_types_supported: ['public', 'pairwise'],
      id_token_signing_alg_values_supported: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt'
      ],
      claims_supported: this.supportedClaims,
      code_challenge_methods_supported: ['plain', 'S256'],
      introspection_endpoint: `${baseUrl}/oauth/introspect`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`
    };
  }

  // Generate UserInfo response
  async getUserInfo(accessToken: string): Promise<UserInfoResponse> {
    // Verify access token
    const payload = await this.oauthService.verifyAccessToken(accessToken);
    
    if (!payload) {
      throw new InvalidTokenError('Invalid access token');
    }

    // Get user data
    const user = await this.userRepository.findById(payload.sub);
    
    if (!user) {
      throw new UserNotFoundError('User not found');
    }

    // Determine which claims to include based on scope
    const scopes = payload.scope?.split(' ') || [];
    const claims: Record<string, any> = {
      sub: user.id
    };

    if (scopes.includes('profile')) {
      claims.name = user.name;
      claims.given_name = user.firstName;
      claims.family_name = user.lastName;
      claims.preferred_username = user.username;
      claims.profile = `${process.env.APP_URL}/users/${user.username}`;
      claims.picture = user.avatar;
      claims.website = user.website;
      claims.gender = user.gender;
      claims.birthdate = user.birthdate;
      claims.zoneinfo = user.timezone;
      claims.locale = user.locale;
      claims.updated_at = Math.floor(user.updatedAt.getTime() / 1000);
    }

    if (scopes.includes('email')) {
      claims.email = user.email;
      claims.email_verified = user.emailVerified;
    }

    if (scopes.includes('address')) {
      claims.address = {
        formatted: user.address?.formatted,
        street_address: user.address?.street,
        locality: user.address?.city,
        region: user.address?.state,
        postal_code: user.address?.postalCode,
        country: user.address?.country
      };
    }

    if (scopes.includes('phone')) {
      claims.phone_number = user.phone;
      claims.phone_number_verified = user.phoneVerified;
    }

    return claims;
  }

  // Generate ID Token
  async generateIdToken(
    user: User,
    clientId: string,
    nonce?: string,
    accessTokenHash?: string,
    codeHash?: string
  ): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const jti = randomBytes(16).toString('hex');

    const payload: IDTokenPayload = {
      iss: process.env.JWT_ISSUER,
      sub: user.id,
      aud: clientId,
      exp: now + 3600, // 1 hour
      iat: now,
      auth_time: now,
      nonce,
      acr: 'urn:mace:incommon:iap:bronze', // Authentication Context Class Reference
      amr: ['pwd'], // Authentication Methods References
      azp: clientId, // Authorized party
      jti,
      at_hash: accessTokenHash,
      c_hash: codeHash
    };

    // Add claims based on requested scope
    const client = await this.clientRepository.findById(clientId);
    if (client?.claims) {
      Object.assign(payload, this.extractClaims(user, client.claims));
    }

    // Sign with private key
    const privateKey = await this.jwksService.getPrivateKey();
    
    return new JWT.Sign(payload)
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        kid: privateKey.kid
      })
      .sign(privateKey.key);
  }

  // Generate JWKS (JSON Web Key Set)
  async getJwks(): Promise<JWKS> {
    const keys = await this.jwksService.getPublicKeys();
    
    return {
      keys: keys.map(key => ({
        kty: key.kty,
        use: key.use,
        kid: key.kid,
        alg: key.alg,
        n: key.n,
        e: key.e,
        x5c: key.x5c,
        x5t: key.x5t,
        'x5t#S256': key['x5t#S256']
      }))
    };
  }

  // Dynamic client registration (RFC 7591)
  async registerClient(
    metadata: ClientMetadata,
    softwareStatement?: string
  ): Promise<RegisteredClient> {
    // Validate software statement if provided
    if (softwareStatement) {
      const statement = await this.validateSoftwareStatement(softwareStatement);
      metadata = { ...statement, ...metadata };
    }

    // Validate metadata
    this.validateClientMetadata(metadata);

    // Generate client credentials
    const clientId = randomBytes(16).toString('hex');
    const clientSecret = metadata.token_endpoint_auth_method === 'none' 
      ? undefined 
      : randomBytes(32).toString('hex');

    // Create client
    const client: OAuthClient = {
      id: clientId,
      secret: clientSecret,
      name: metadata.client_name || '',
      redirectUris: metadata.redirect_uris || [],
      grants: metadata.grant_types || ['authorization_code'],
      scopes: metadata.scope?.split(' ') || ['openid'],
      accessTokenLifetime: 3600,
      refreshTokenLifetime: 86400 * 30,
      confidential: metadata.token_endpoint_auth_method !== 'none',
      trusted: false
    };

    await this.clientRepository.save(client);

    return {
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_secret_expires_at: 0, // Never expires
      registration_client_uri: `${process.env.APP_URL}/oauth/register/${clientId}`,
      registration_access_token: randomBytes(32).toString('hex')
    };
  }

  // Private helper methods
  private extractClaims(user: User, requestedClaims: any): Record<string, any> {
    const claims: Record<string, any> = {};

    if (requestedClaims.id_token) {
      for (const [claim, config] of Object.entries(requestedClaims.id_token)) {
        if (typeof config === 'object' && (config as any).essential) {
          const value = this.getClaimValue(user, claim);
          if (value !== undefined) {
            claims[claim] = value;
          }
        }
      }
    }

    if (requestedClaims.userinfo) {
      for (const [claim, config] of Object.entries(requestedClaims.userinfo)) {
        if (typeof config === 'object' && (config as any).essential) {
          const value = this.getClaimValue(user, claim);
          if (value !== undefined) {
            claims[claim] = value;
          }
        }
      }
    }

    return claims;
  }

  private getClaimValue(user: User, claim: string): any {
    const claimMap: Record<string, any> = {
      sub: user.id,
      name: user.name,
      given_name: user.firstName,
      family_name: user.lastName,
      middle_name: user.middleName,
      nickname: user.nickname,
      preferred_username: user.username,
      profile: user.profileUrl,
      picture: user.avatar,
      website: user.website,
      email: user.email,
      email_verified: user.emailVerified,
      gender: user.gender,
      birthdate: user.birthdate,
      zoneinfo: user.timezone,
      locale: user.locale,
      phone_number: user.phone,
      phone_number_verified: user.phoneVerified,
      address: user.address,
      updated_at: Math.floor(user.updatedAt.getTime() / 1000)
    };

    return claimMap[claim];
  }

  private validateClientMetadata(metadata: ClientMetadata): void {
    // Required fields
    if (!metadata.redirect_uris || metadata.redirect_uris.length === 0) {
      throw new InvalidClientMetadataError('redirect_uris is required');
    }

    // Validate redirect URIs
    for (const uri of metadata.redirect_uris) {
      try {
        const url = new URL(uri);
        
        if (url.protocol !== 'https:' && process.env.NODE_ENV === 'production') {
          throw new InvalidClientMetadataError('Redirect URIs must use HTTPS in production');
        }
        
        // Prevent open redirects
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
          continue;
        }
        
        if (!url.hostname.includes('.')) {
          throw new InvalidClientMetadataError('Invalid redirect URI hostname');
        }
      } catch {
        throw new InvalidClientMetadataError('Invalid redirect URI format');
      }
    }

    // Validate response types
    if (metadata.response_types) {
      const validResponseTypes = ['code', 'token', 'id_token'];
      for (const type of metadata.response_types) {
        if (!validResponseTypes.includes(type)) {
          throw new InvalidClientMetadataError(`Invalid response type: ${type}`);
        }
      }
    }

    // Validate grant types
    if (metadata.grant_types) {
      const validGrantTypes = [
        'authorization_code',
        'implicit',
        'password',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code'
      ];
      
      for (const type of metadata.grant_types) {
        if (!validGrantTypes.includes(type)) {
          throw new InvalidClientMetadataError(`Invalid grant type: ${type}`);
        }
      }
    }

    // Validate token endpoint auth method
    if (metadata.token_endpoint_auth_method) {
      const validMethods = [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
        'none'
      ];
      
      if (!validMethods.includes(metadata.token_endpoint_auth_method)) {
        throw new InvalidClientMetadataError('Invalid token endpoint auth method');
      }
    }
  }

  private async validateSoftwareStatement(statement: string): Promise<ClientMetadata> {
    try {
      const payload = await JWT.verify(statement, this.jwksService.getPublicKey(), {
        issuer: 'https://trusted-issuer.com',
        audience: process.env.APP_URL
      });

      return payload as ClientMetadata;
    } catch (error) {
      throw new InvalidSoftwareStatementError('Invalid software statement');
    }
  }
}
```

## Role-Based Access Control (RBAC)

### 🏛️ RBAC System Architecture

```typescript
// types/rbac.types.ts
export enum PermissionAction {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  MANAGE = 'manage',
  APPROVE = 'approve',
  EXPORT = 'export',
  IMPORT = 'import'
}

export interface Permission {
  id: string;
  resource: string;
  action: PermissionAction;
  conditions?: PermissionCondition[];
  description?: string;
}

export interface PermissionCondition {
  field: string;
  operator: 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'not_in' | 'contains';
  value: any;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: string[]; // Permission IDs
  inheritedRoles?: string[]; // Role IDs
  isDefault: boolean;
}

export interface UserRoleAssignment {
  userId: string;
  roleId: string;
  assignedAt: Date;
  assignedBy?: string;
  expiresAt?: Date;
  context?: Record<string, any>; // Context-specific role assignment
}
```

### 🛡️ RBAC Implementation

```typescript
// services/rbac.service.ts
import { Redis } from 'ioredis';
import { addDays, isAfter } from 'date-fns';

export class RBACService {
  private readonly cacheTtl = 5 * 60; // 5 minutes cache
  private readonly permissionCachePrefix = 'permissions:';
  private readonly roleCachePrefix = 'roles:';

  constructor(
    private redis: Redis,
    private permissionRepository: PermissionRepository,
    private roleRepository: RoleRepository,
    private userRoleRepository: UserRoleRepository
  ) {}

  // Check if user has permission
  async hasPermission(
    userId: string,
    resource: string,
    action: PermissionAction,
    context?: Record<string, any>
  ): Promise<{
    allowed: boolean;
    conditions?: PermissionCondition[];
    reason?: string;
  }> {
    // Get user's roles
    const userRoles = await this.getUserRoles(userId);
    
    if (userRoles.length === 0) {
      return {
        allowed: false,
        reason: 'User has no roles assigned'
      };
    }

    // Get all permissions for user's roles
    const userPermissions = await this.getUserPermissions(userId);

    // Find matching permission
    const matchingPermission = userPermissions.find(p => 
      p.resource === resource && p.action === action
    );

    if (!matchingPermission) {
      return {
        allowed: false,
        reason: 'Permission not found'
      };
    }

    // Check conditions if present
    if (matchingPermission.conditions && matchingPermission.conditions.length > 0) {
      const conditionsMet = this.checkConditions(
        matchingPermission.conditions,
        context
      );

      if (!conditionsMet) {
        return {
          allowed: false,
          reason: 'Conditions not met',
          conditions: matchingPermission.conditions
        };
      }
    }

    return {
      allowed: true,
      conditions: matchingPermission.conditions
    };
  }

  // Check multiple permissions
  async checkPermissions(
    userId: string,
    permissions: Array<{ resource: string; action: PermissionAction }>,
    context?: Record<string, any>
  ): Promise<{
    allowed: boolean;
    failedPermissions: Array<{ resource: string; action: PermissionAction; reason: string }>;
  }> {
    const results = await Promise.all(
      permissions.map(async permission => {
        const result = await this.hasPermission(
          userId,
          permission.resource,
          permission.action,
          context
        );
        
        return {
          ...permission,
          allowed: result.allowed,
          reason: result.reason
        };
      })
    );

    const failedPermissions = results
      .filter(r => !r.allowed)
      .map(({ resource, action, reason }) => ({ resource, action, reason: reason || 'Unknown' }));

    return {
      allowed: failedPermissions.length === 0,
      failedPermissions
    };
  }

  // Assign role to user
  async assignRoleToUser(
    userId: string,
    roleId: string,
    assignedBy?: string,
    options: {
      expiresAt?: Date;
      context?: Record<string, any>;
    } = {}
  ): Promise<void> {
    const role = await this.roleRepository.findById(roleId);
    
    if (!role) {
      throw new RoleNotFoundError('Role not found');
    }

    // Check if user already has this role
    const existingAssignment = await this.userRoleRepository.findByUserAndRole(
      userId,
      roleId
    );

    if (existingAssignment) {
      // Update existing assignment
      existingAssignment.assignedBy = assignedBy;
      existingAssignment.expiresAt = options.expiresAt;
      existingAssignment.context = options.context;
      
      await this.userRoleRepository.update(existingAssignment.id, existingAssignment);
    } else {
      // Create new assignment
      const assignment: UserRoleAssignment = {
        userId,
        roleId,
        assignedAt: new Date(),
        assignedBy,
        expiresAt: options.expiresAt,
        context: options.context
      };

      await this.userRoleRepository.create(assignment);
    }

    // Clear cache
    await this.clearUserCache(userId);
  }

  // Remove role from user
  async removeRoleFromUser(userId: string, roleId: string): Promise<void> {
    const assignment = await this.userRoleRepository.findByUserAndRole(userId, roleId);
    
    if (assignment) {
      await this.userRoleRepository.delete(assignment.id);
      await this.clearUserCache(userId);
    }
  }

  // Get user's effective permissions (including inherited roles)
  async getUserPermissions(userId: string): Promise<Permission[]> {
    const cacheKey = `${this.permissionCachePrefix}${userId}`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get user's roles
    const userRoles = await this.getUserRoles(userId);
    
    if (userRoles.length === 0) {
      return [];
    }

    // Get all permissions for user's roles (including inherited)
    const allPermissions = new Map<string, Permission>();

    for (const role of userRoles) {
      const rolePermissions = await this.getRolePermissions(role.id);
      
      for (const permission of rolePermissions) {
        if (!allPermissions.has(permission.id)) {
          allPermissions.set(permission.id, permission);
        }
      }
    }

    const permissions = Array.from(allPermissions.values());

    // Cache the result
    await this.redis.setex(cacheKey, this.cacheTtl, JSON.stringify(permissions));

    return permissions;
  }

  // Create role with permissions
  async createRole(
    name: string,
    permissionIds: string[],
    options: {
      description?: string;
      inheritedRoles?: string[];
      isDefault?: boolean;
    } = {}
  ): Promise<Role> {
    // Validate permissions exist
    const permissions = await this.permissionRepository.findByIds(permissionIds);
    
    if (permissions.length !== permissionIds.length) {
      throw new PermissionNotFoundError('Some permissions not found');
    }

    // Validate inherited roles exist
    if (options.inheritedRoles) {
      const inheritedRoles = await this.roleRepository.findByIds(options.inheritedRoles);
      
      if (inheritedRoles.length !== options.inheritedRoles.length) {
        throw new RoleNotFoundError('Some inherited roles not found');
      }
    }

    const role: Role = {
      id: this.generateId(),
      name,
      description: options.description,
      permissions: permissionIds,
      inheritedRoles: options.inheritedRoles,
      isDefault: options.isDefault || false
    };

    await this.roleRepository.create(role);

    return role;
  }

  // Update role permissions
  async updateRolePermissions(
    roleId: string,
    permissionIds: string[]
  ): Promise<void> {
    const role = await this.roleRepository.findById(roleId);
    
    if (!role) {
      throw new RoleNotFoundError('Role not found');
    }

    // Validate permissions exist
    const permissions = await this.permissionRepository.findByIds(permissionIds);
    
    if (permissions.length !== permissionIds.length) {
      throw new PermissionNotFoundError('Some permissions not found');
    }

    role.permissions = permissionIds;
    await this.roleRepository.update(roleId, role);

    // Clear cache for all users with this role
    await this.clearRoleCache(roleId);
  }

  // Check permission with ABAC-like conditions
  async checkPermissionWithAttributes(
    userId: string,
    resource: string,
    action: PermissionAction,
    resourceAttributes: Record<string, any>,
    userAttributes: Record<string, any>
  ): Promise<boolean> {
    const { allowed, conditions } = await this.hasPermission(
      userId,
      resource,
      action,
      { ...resourceAttributes, user: userAttributes }
    );

    if (!allowed || !conditions) {
      return allowed;
    }

    // Evaluate conditions with both resource and user attributes
    const context = { ...resourceAttributes, user: userAttributes };
    return this.checkConditions(conditions, context);
  }

  // Private helper methods
  private async getUserRoles(userId: string): Promise<Role[]> {
    const cacheKey = `${this.roleCachePrefix}${userId}`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get user's role assignments
    const assignments = await this.userRoleRepository.findByUser(userId);
    const currentTime = new Date();

    // Filter active assignments (not expired)
    const activeAssignments = assignments.filter(assignment => {
      if (!assignment.expiresAt) {
        return true;
      }
      return isAfter(assignment.expiresAt, currentTime);
    });

    // Get role details
    const roleIds = activeAssignments.map(a => a.roleId);
    const roles = await this.roleRepository.findByIds(roleIds);

    // Expand inherited roles
    const allRoles = await this.expandInheritedRoles(roles);

    // Cache the result
    await this.redis.setex(cacheKey, this.cacheTtl, JSON.stringify(allRoles));

    return allRoles;
  }

  private async getRolePermissions(roleId: string): Promise<Permission[]> {
    const role = await this.roleRepository.findById(roleId);
    
    if (!role) {
      return [];
    }

    // Get direct permissions
    const permissions = await this.permissionRepository.findByIds(role.permissions);

    // Get permissions from inherited roles
    if (role.inheritedRoles && role.inheritedRoles.length > 0) {
      for (const inheritedRoleId of role.inheritedRoles) {
        const inheritedPermissions = await this.getRolePermissions(inheritedRoleId);
        permissions.push(...inheritedPermissions);
      }
    }

    // Remove duplicates
    const uniquePermissions = Array.from(
      new Map(permissions.map(p => [p.id, p])).values()
    );

    return uniquePermissions;
  }

  private async expandInheritedRoles(roles: Role[]): Promise<Role[]> {
    const allRoles = new Map<string, Role>();
    
    const expand = async (role: Role) => {
      if (allRoles.has(role.id)) {
        return;
      }

      allRoles.set(role.id, role);

      if (role.inheritedRoles && role.inheritedRoles.length > 0) {
        const inheritedRoles = await this.roleRepository.findByIds(role.inheritedRoles);
        
        for (const inheritedRole of inheritedRoles) {
          await expand(inheritedRole);
        }
      }
    };

    for (const role of roles) {
      await expand(role);
    }

    return Array.from(allRoles.values());
  }

  private checkConditions(
    conditions: PermissionCondition[],
    context?: Record<string, any>
  ): boolean {
    if (!context) {
      return false;
    }

    for (const condition of conditions) {
      const value = this.getValueFromContext(context, condition.field);
      
      if (!this.evaluateCondition(value, condition.operator, condition.value)) {
        return false;
      }
    }

    return true;
  }

  private getValueFromContext(context: Record<string, any>, path: string): any {
    const parts = path.split('.');
    let value = context;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  private evaluateCondition(
    value: any,
    operator: string,
    expected: any
  ): boolean {
    switch (operator) {
      case 'eq':
        return value === expected;
      case 'neq':
        return value !== expected;
      case 'gt':
        return value > expected;
      case 'lt':
        return value < expected;
      case 'gte':
        return value >= expected;
      case 'lte':
        return value <= expected;
      case 'in':
        return Array.isArray(expected) && expected.includes(value);
      case 'not_in':
        return Array.isArray(expected) && !expected.includes(value);
      case 'contains':
        return value && typeof value === 'string' && value.includes(expected);
      default:
        return false;
    }
  }

  private generateId(): string {
    return randomBytes(16).toString('hex');
  }

  private async clearUserCache(userId: string): Promise<void> {
    const permissionKey = `${this.permissionCachePrefix}${userId}`;
    const roleKey = `${this.roleCachePrefix}${userId}`;
    
    await Promise.all([
      this.redis.del(permissionKey),
      this.redis.del(roleKey)
    ]);
  }

  private async clearRoleCache(roleId: string): Promise<void> {
    // This is more complex - would need to clear cache for all users with this role
    // In production, you might want to use a different caching strategy
  }
}
```

### 🔒 RBAC Middleware

```typescript
// middleware/rbac.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { RBACService } from '@/services/rbac.service';
import { PermissionAction } from '@/types/rbac.types';

export const requirePermission = (
  resource: string,
  action: PermissionAction,
  options: {
    extractResourceId?: (req: Request) => string | undefined;
    extractAttributes?: (req: Request) => Record<string, any>;
    allowSelf?: boolean;
  } = {}
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.sub;
      
      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const rbacService = req.container.resolve(RBACService);

      // Extract resource attributes
      let resourceAttributes: Record<string, any> = {};
      
      if (options.extractResourceId) {
        const resourceId = options.extractResourceId(req);
        if (resourceId) {
          resourceAttributes.id = resourceId;
        }
      }

      if (options.extractAttributes) {
        resourceAttributes = {
          ...resourceAttributes,
          ...options.extractAttributes(req)
        };
      }

      // Allow self-access if configured
      if (options.allowSelf && resourceAttributes.id === userId) {
        return next();
      }

      // Extract user attributes
      const userAttributes = {
        id: req.user?.sub,
        email: req.user?.email,
        role: req.user?.role,
        permissions: req.user?.permissions
      };

      // Check permission
      const hasPermission = await rbacService.checkPermissionWithAttributes(
        userId,
        resource,
        action,
        resourceAttributes,
        userAttributes
      );

      if (!hasPermission) {
        return res.status(403).json({ 
          error: 'Access denied',
          details: `You need ${action} permission on ${resource}`
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Resource-based middleware
export const resourcePermission = (
  resourceExtractor: (req: Request) => string,
  action: PermissionAction
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const resource = resourceExtractor(req);
      const userId = req.user?.sub;

      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const rbacService = req.container.resolve(RBACService);

      const { allowed } = await rbacService.hasPermission(
        userId,
        resource,
        action,
        req.body
      );

      if (!allowed) {
        return res.status(403).json({ 
          error: 'Access denied',
          resource,
          action
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Role-based middleware
export const requireRole = (roleName: string) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userRole = req.user?.role;
      
      if (!userRole) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      if (userRole !== roleName) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          requiredRole: roleName,
          userRole
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Multiple roles middleware
export const requireAnyRole = (roleNames: string[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userRole = req.user?.role;
      
      if (!userRole) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      if (!roleNames.includes(userRole)) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          requiredRoles: roleNames,
          userRole
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Scoped permissions middleware
export const requireScopedPermission = (
  scope: string,
  options: {
    requireAll?: boolean;
  } = {}
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userPermissions = req.user?.permissions || [];
      const requiredPermissions = scope.split(' ');
      
      if (options.requireAll) {
        // User must have all required permissions
        const hasAll = requiredPermissions.every(p => userPermissions.includes(p));
        
        if (!hasAll) {
          return res.status(403).json({ 
            error: 'Missing required permissions',
            requiredPermissions,
            userPermissions
          });
        }
      } else {
        // User must have at least one required permission
        const hasAny = requiredPermissions.some(p => userPermissions.includes(p));
        
        if (!hasAny) {
          return res.status(403).json({ 
            error: 'Missing required permissions',
            requiredPermissions,
            userPermissions
          });
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
```

## Two-Factor Authentication (2FA)

### 🔐 2FA Implementation

```typescript
// types/2fa.types.ts
export enum TwoFactorMethod {
  TOTP = 'totp',
  SMS = 'sms',
  EMAIL = 'email',
  RECOVERY_CODE = 'recovery_code',
  WEB_AUTHN = 'webauthn'
}

export interface TwoFactorConfig {
  enabled: boolean;
  required: boolean;
  methods: TwoFactorMethod[];
  backupCodesCount: number;
  backupCodeLength: number;
  totp: {
    issuer: string;
    digits: number;
    period: number;
    algorithm: string;
  };
  sms: {
    provider: string;
    template: string;
  };
  email: {
    template: string;
    subject: string;
  };
}

export interface TwoFactorState {
  userId: string;
  method: TwoFactorMethod;
  secret?: string; // For TOTP
  phoneNumber?: string; // For SMS
  verified: boolean;
  enabledAt?: Date;
  lastUsed?: Date;
  backupCodes?: string[];
  recoveryCodes?: string[];
}
```

### 🛠️ 2FA Service

```typescript
// services/two-factor.service.ts
import * as OTPAuth from 'otpauth';
import { randomBytes, randomInt } from 'crypto';
import { authenticator } from 'otplib';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

export class TwoFactorService {
  private readonly config: TwoFactorConfig = {
    enabled: true,
    required: false,
    methods: [TwoFactorMethod.TOTP, TwoFactorMethod.EMAIL, TwoFactorMethod.RECOVERY_CODE],
    backupCodesCount: 10,
    backupCodeLength: 8,
    totp: {
      issuer: process.env.APP_NAME || 'MyApp',
      digits: 6,
      period: 30,
      algorithm: 'SHA1'
    },
    sms: {
      provider: 'twilio',
      template: 'Your verification code is: {code}'
    },
    email: {
      template: '2fa-email',
      subject: 'Your Verification Code'
    }
  };

  // Initialize 2FA for user
  async initialize(userId: string, method: TwoFactorMethod): Promise<{
    secret?: string;
    qrCode?: string;
    backupCodes?: string[];
    phoneNumber?: string;
  }> {
    switch (method) {
      case TwoFactorMethod.TOTP:
        return this.initializeTOTP(userId);
      
      case TwoFactorMethod.SMS:
        return this.initializeSMS(userId);
      
      case TwoFactorMethod.EMAIL:
        return this.initializeEmail(userId);
      
      case TwoFactorMethod.RECOVERY_CODE:
        return this.initializeRecoveryCodes(userId);
      
      default:
        throw new Error(`Unsupported 2FA method: ${method}`);
    }
  }

  // Initialize TOTP
  private async initializeTOTP(userId: string): Promise<{
    secret: string;
    qrCode: string;
    backupCodes: string[];
  }> {
    // Generate secret
    const secret = authenticator.generateSecret();
    
    // Generate TOTP URL
    const totp = new OTPAuth.TOTP({
      issuer: this.config.totp.issuer,
      label: userId,
      algorithm: this.config.totp.algorithm as 'SHA1' | 'SHA256' | 'SHA512',
      digits: this.config.totp.digits,
      period: this.config.totp.period,
      secret
    });

    const otpUrl = totp.toString();
    
    // Generate QR code
    const qrCode = await QRCode.toDataURL(otpUrl);

    // Generate backup codes
    const backupCodes = this.generateBackupCodes();

    // Store in database (encrypted)
    await this.twoFactorRepository.save({
      userId,
      method: TwoFactorMethod.TOTP,
      secret: this.encryptSecret(secret),
      verified: false,
      backupCodes: backupCodes.map(code => this.hashBackupCode(code))
    });

    return {
      secret,
      qrCode,
      backupCodes
    };
  }

  // Initialize SMS 2FA
  private async initializeSMS(userId: string): Promise<{
    phoneNumber?: string;
  }> {
    const user = await this.userRepository.findById(userId);
    
    if (!user?.phoneNumber) {
      throw new Error('Phone number not found for user');
    }

    // Verify phone number is valid
    if (!this.isValidPhoneNumber(user.phoneNumber)) {
      throw new Error('Invalid phone number');
    }

    // Store in database
    await this.twoFactorRepository.save({
      userId,
      method: TwoFactorMethod.SMS,
      phoneNumber: user.phoneNumber,
      verified: false
    });

    return {
      phoneNumber: this.maskPhoneNumber(user.phoneNumber)
    };
  }

  // Initialize Email 2FA
  private async initializeEmail(userId: string): Promise<{}> {
    const user = await this.userRepository.findById(userId);
    
    if (!user?.email) {
      throw new Error('Email not found for user');
    }

    // Store in database
    await this.twoFactorRepository.save({
      userId,
      method: TwoFactorMethod.EMAIL,
      verified: false
    });

    return {};
  }

  // Generate recovery codes
  private async initializeRecoveryCodes(userId: string): Promise<{
    recoveryCodes: string[];
  }> {
    const recoveryCodes = this.generateRecoveryCodes();

    // Store hashed codes in database
    await this.twoFactorRepository.save({
      userId,
      method: TwoFactorMethod.RECOVERY_CODE,
      verified: false,
      recoveryCodes: recoveryCodes.map(code => this.hashRecoveryCode(code))
    });

    return { recoveryCodes };
  }

  // Verify 2FA code
  async verify(
    userId: string,
    method: TwoFactorMethod,
    code: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<{
    success: boolean;
    remainingAttempts?: number;
    isBackupCode?: boolean;
    isRecoveryCode?: boolean;
  }> {
    // Get 2FA state
    const state = await this.twoFactorRepository.findByUserAndMethod(userId, method);
    
    if (!state) {
      throw new TwoFactorNotSetupError('2FA not setup for this method');
    }

    // Check rate limiting
    const rateLimit = await this.checkRateLimit(userId, method);
    
    if (!rateLimit.allowed) {
      throw new RateLimitError('Too many verification attempts');
    }

    let isValid = false;
    let isBackupCode = false;
    let isRecoveryCode = false;

    switch (method) {
      case TwoFactorMethod.TOTP:
        // Check if it's a backup code
        if (state.backupCodes) {
          const backupCodeMatch = state.backupCodes.some(hashedCode => 
            this.verifyBackupCode(code, hashedCode)
          );
          
          if (backupCodeMatch) {
            isValid = true;
            isBackupCode = true;
            // Remove used backup code
            await this.removeBackupCode(state, code);
          }
        }

        // If not a backup code, check TOTP
        if (!isValid) {
          const secret = this.decryptSecret(state.secret!);
          isValid = this.verifyTOTP(secret, code);
        }
        break;

      case TwoFactorMethod.SMS:
      case TwoFactorMethod.EMAIL:
        // Check verification code from database
        isValid = await this.verifyStoredCode(userId, method, code);
        break;

      case TwoFactorMethod.RECOVERY_CODE:
        if (state.recoveryCodes) {
          isValid = state.recoveryCodes.some(hashedCode => 
            this.verifyRecoveryCode(code, hashedCode)
          );
          
          if (isValid) {
            isRecoveryCode = true;
            // Remove used recovery code
            await this.removeRecoveryCode(state, code);
          }
        }
        break;
    }

    if (isValid) {
      // Mark as verified if not already
      if (!state.verified) {
        await this.twoFactorRepository.update(state.id, {
          verified: true,
          enabledAt: new Date()
        });
      }

      // Update last used
      await this.twoFactorRepository.update(state.id, {
        lastUsed: new Date()
      });

      // Log successful verification
      await this.auditLogger.log({
        userId,
        action: '2fa_verified',
        method,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date()
      });

      // Reset rate limit on success
      await this.resetRateLimit(userId, method);

      return {
        success: true,
        isBackupCode,
        isRecoveryCode
      };
    } else {
      // Increment failed attempts
      await this.incrementFailedAttempts(userId, method);

      // Get remaining attempts
      const attempts = await this.getFailedAttempts(userId, method);
      const remainingAttempts = Math.max(0, 5 - attempts);

      // Log failed attempt
      await this.auditLogger.log({
        userId,
        action: '2fa_failed',
        method,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date()
      });

      // Lock account if too many failed attempts
      if (attempts >= 5) {
        await this.lockAccount(userId, {
          reason: 'too_many_2fa_failures',
          duration: 15 * 60 * 1000 // 15 minutes
        });
      }

      return {
        success: false,
        remainingAttempts
      };
    }
  }

  // Send verification code
  async sendVerificationCode(
    userId: string,
    method: TwoFactorMethod.SMS | TwoFactorMethod.EMAIL
  ): Promise<void> {
    const state = await this.twoFactorRepository.findByUserAndMethod(userId, method);
    
    if (!state) {
      throw new TwoFactorNotSetupError('2FA not setup for this method');
    }

    // Generate code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store code in database
    await this.verificationCodeRepository.save({
      userId,
      method,
      code: this.hashVerificationCode(code),
      expiresAt,
      used: false
    });

    // Send code
    switch (method) {
      case TwoFactorMethod.SMS:
        await this.sendSmsCode(state.phoneNumber!, code);
        break;
      
      case TwoFactorMethod.EMAIL:
        const user = await this.userRepository.findById(userId);
        await this.sendEmailCode(user!.email, code);
        break;
    }

    // Log sending
    await this.auditLogger.log({
      userId,
      action: '2fa_code_sent',
      method,
      timestamp: new Date()
    });
  }

  // Disable 2FA for user
  async disable(userId: string, method?: TwoFactorMethod): Promise<void> {
    if (method) {
      // Disable specific method
      await this.twoFactorRepository.disableMethod(userId, method);
    } else {
      // Disable all methods
      await this.twoFactorRepository.disableAll(userId);
    }

    // Log action
    await this.auditLogger.log({
      userId,
      action: '2fa_disabled',
      method,
      timestamp: new Date()
    });
  }

  // Get 2FA status for user
  async getStatus(userId: string): Promise<{
    enabled: boolean;
    required: boolean;
    methods: Array<{
      method: TwoFactorMethod;
      verified: boolean;
      enabledAt?: Date;
      lastUsed?: Date;
    }>;
    backupCodesRemaining: number;
  }> {
    const states = await this.twoFactorRepository.findByUser(userId);
    
    const methods = states.map(state => ({
      method: state.method,
      verified: state.verified,
      enabledAt: state.enabledAt,
      lastUsed: state.lastUsed
    }));

    const backupCodesRemaining = states
      .find(s => s.method === TwoFactorMethod.TOTP)
      ?.backupCodes?.length || 0;

    return {
      enabled: methods.some(m => m.verified),
      required: this.config.required,
      methods,
      backupCodesRemaining
    };
  }

  // Generate new backup codes
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    const state = await this.twoFactorRepository.findByUserAndMethod(
      userId,
      TwoFactorMethod.TOTP
    );

    if (!state) {
      throw new TwoFactorNotSetupError('TOTP not setup');
    }

    const backupCodes = this.generateBackupCodes();
    
    await this.twoFactorRepository.update(state.id, {
      backupCodes: backupCodes.map(code => this.hashBackupCode(code))
    });

    return backupCodes;
  }

  // Private helper methods
  private verifyTOTP(secret: string, code: string): boolean {
    // Use window for time drift
    const window = 1; // Accept codes from previous and next 30-second window
    
    return authenticator.verify({
      secret,
      token: code,
      window
    });
  }

  private async verifyStoredCode(
    userId: string,
    method: TwoFactorMethod,
    code: string
  ): Promise<boolean> {
    const verification = await this.verificationCodeRepository.findValid(
      userId,
      method
    );

    if (!verification) {
      return false;
    }

    // Check if expired
    if (new Date() > verification.expiresAt) {
      await this.verificationCodeRepository.markAsUsed(verification.id);
      return false;
    }

    // Verify code
    const isValid = this.verifyVerificationCode(code, verification.code);
    
    if (isValid) {
      await this.verificationCodeRepository.markAsUsed(verification.id);
    }

    return isValid;
  }

  private generateVerificationCode(): string {
    // Generate 6-digit code
    return randomInt(100000, 999999).toString();
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    
    for (let i = 0; i < this.config.backupCodesCount; i++) {
      const code = randomBytes(this.config.backupCodeLength)
        .toString('hex')
        .slice(0, this.config.backupCodeLength)
        .toUpperCase();
      
      codes.push(code);
    }

    return codes;
  }

  private generateRecoveryCodes(): string[] {
    const codes: string[] = [];
    
    for (let i = 0; i < 10; i++) {
      // Format: XXXX-XXXX-XXXX
      const parts = [
        randomBytes(2).toString('hex').toUpperCase(),
        randomBytes(2).toString('hex').toUpperCase(),
        randomBytes(2).toString('hex').toUpperCase()
      ];
      
      codes.push(parts.join('-'));
    }

    return codes;
  }

  private encryptSecret(secret: string): string {
    // Implement encryption (e.g., using crypto module)
    const cipher = createCipher('aes-256-gcm', process.env.ENCRYPTION_KEY!);
    return cipher.update(secret, 'utf8', 'hex') + cipher.final('hex');
  }

  private decryptSecret(encrypted: string): string {
    const decipher = createDecipher('aes-256-gcm', process.env.ENCRYPTION_KEY!);
    return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
  }

  private hashBackupCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  private hashRecoveryCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  private hashVerificationCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }

  private verifyBackupCode(code: string, hashedCode: string): boolean {
    const hash = this.hashBackupCode(code);
    return timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(hashedCode, 'hex')
    );
  }

  private verifyRecoveryCode(code: string, hashedCode: string): boolean {
    const hash = this.hashRecoveryCode(code);
    return timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(hashedCode, 'hex')
    );
  }

  private verifyVerificationCode(code: string, hashedCode: string): boolean {
    const hash = this.hashVerificationCode(code);
    return timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(hashedCode, 'hex')
    );
  }

  private async removeBackupCode(state: TwoFactorState, code: string): Promise<void> {
    const hashedCode = this.hashBackupCode(code);
    const updatedBackupCodes = state.backupCodes?.filter(hc => hc !== hashedCode) || [];
    
    await this.twoFactorRepository.update(state.id, {
      backupCodes: updatedBackupCodes
    });
  }

  private async removeRecoveryCode(state: TwoFactorState, code: string): Promise<void> {
    const hashedCode = this.hashRecoveryCode(code);
    const updatedRecoveryCodes = state.recoveryCodes?.filter(hc => hc !== hashedCode) || [];
    
    await this.twoFactorRepository.update(state.id, {
      recoveryCodes: updatedRecoveryCodes
    });
  }

  private async checkRateLimit(
    userId: string,
    method: TwoFactorMethod
  ): Promise<{ allowed: boolean; resetAt?: Date }> {
    const key = `rate_limit:2fa:${userId}:${method}`;
    const attempts = await this.redis.get(key);
    
    if (!attempts) {
      await this.redis.setex(key, 15 * 60, '1'); // 15 minutes
      return { allowed: true };
    }

    const count = parseInt(attempts, 10);
    
    if (count >= 5) {
      const ttl = await this.redis.ttl(key);
      return {
        allowed: false,
        resetAt: new Date(Date.now() + ttl * 1000)
      };
    }

    await this.redis.incr(key);
    return { allowed: true };
  }

  private async incrementFailedAttempts(
    userId: string,
    method: TwoFactorMethod
  ): Promise<void> {
    const key = `2fa_failed:${userId}:${method}`;
    await this.redis.incr(key);
    await this.redis.expire(key, 15 * 60); // 15 minutes
  }

  private async getFailedAttempts(
    userId: string,
    method: TwoFactorMethod
  ): Promise<number> {
    const key = `2fa_failed:${userId}:${method}`;
    const attempts = await this.redis.get(key);
    return attempts ? parseInt(attempts, 10) : 0;
  }

  private async resetRateLimit(
    userId: string,
    method: TwoFactorMethod
  ): Promise<void> {
    const key = `rate_limit:2fa:${userId}:${method}`;
    await this.redis.del(key);
  }
}
```

## Email Login / OTP

### 📧 Email-Based Authentication

```typescript
// types/email-auth.types.ts
export interface EmailLoginConfig {
  otpLength: number;
  otpExpiry: number; // in minutes
  maxAttempts: number;
  rateLimitWindow: number; // in minutes
  allowMagicLinks: boolean;
  magicLinkExpiry: number; // in minutes
}

export interface EmailOTP {
  id: string;
  email: string;
  code: string;
  hashedCode: string;
  expiresAt: Date;
  attempts: number;
  used: boolean;
  usedAt?: Date;
  ipAddress?: string;
  userAgent?: string;
  purpose: 'login' | 'verification' | 'password_reset';
}

export interface MagicLink {
  id: string;
  email: string;
  token: string;
  expiresAt: Date;
  used: boolean;
  usedAt?: Date;
  redirectTo?: string;
  ipAddress?: string;
  userAgent?: string;
}
```

### 🚀 Email Auth Service

```typescript
// services/email-auth.service.ts
import { randomBytes, randomInt, createHash, timingSafeEqual } from 'crypto';
import { addMinutes, isAfter } from 'date-fns';
import { Resend } from 'resend';
import { Redis } from 'ioredis';

export class EmailAuthService {
  private readonly config: EmailLoginConfig = {
    otpLength: 6,
    otpExpiry: 10,
    maxAttempts: 3,
    rateLimitWindow: 15,
    allowMagicLinks: true,
    magicLinkExpiry: 30
  };

  private readonly resend = new Resend(process.env.RESEND_API_KEY);
  private readonly redis: Redis;

  constructor(redis: Redis) {
    this.redis = redis;
  }

  // Send OTP to email
  async sendOTP(
    email: string,
    purpose: 'login' | 'verification' | 'password_reset' = 'login',
    context: {
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<{
    success: boolean;
    expiresAt: Date;
    remainingAttempts: number;
  }> {
    // Rate limiting check
    const rateLimit = await this.checkRateLimit(email, purpose);
    
    if (!rateLimit.allowed) {
      throw new RateLimitError(
        'Too many OTP requests',
        rateLimit.resetAt
      );
    }

    // Cleanup old OTPs for this email and purpose
    await this.cleanupOldOTPs(email, purpose);

    // Generate OTP
    const otp = this.generateOTP();
    const hashedOTP = this.hashOTP(otp);
    const expiresAt = addMinutes(new Date(), this.config.otpExpiry);

    // Store OTP in database
    const emailOTP: EmailOTP = {
      id: randomBytes(16).toString('hex'),
      email,
      code: otp,
      hashedCode: hashedOTP,
      expiresAt,
      attempts: 0,
      used: false,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      purpose
    };

    await this.emailOTPRepository.save(emailOTP);

    // Send email
    await this.sendEmail(email, otp, purpose);

    // Log OTP sent
    await this.auditLogger.log({
      action: 'otp_sent',
      email,
      purpose,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: new Date()
    });

    return {
      success: true,
      expiresAt,
      remainingAttempts: this.config.maxAttempts
    };
  }

  // Verify OTP
  async verifyOTP(
    email: string,
    code: string,
    purpose: 'login' | 'verification' | 'password_reset' = 'login',
    context: {
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<{
    success: boolean;
    isValid: boolean;
    isExpired: boolean;
    remainingAttempts: number;
    user?: User;
    token?: string;
  }> {
    // Get the most recent OTP for this email and purpose
    const otp = await this.emailOTPRepository.findLatest(email, purpose);
    
    if (!otp) {
      return {
        success: false,
        isValid: false,
        isExpired: false,
        remainingAttempts: 0
      };
    }

    // Check if OTP is expired
    if (isAfter(new Date(), otp.expiresAt)) {
      await this.emailOTPRepository.markAsExpired(otp.id);
      
      return {
        success: false,
        isValid: false,
        isExpired: true,
        remainingAttempts: 0
      };
    }

    // Check if OTP was already used
    if (otp.used) {
      return {
        success: false,
        isValid: false,
        isExpired: false,
        remainingAttempts: 0
      };
    }

    // Check attempt limit
    if (otp.attempts >= this.config.maxAttempts) {
      await this.emailOTPRepository.markAsBlocked(otp.id);
      
      return {
        success: false,
        isValid: false,
        isExpired: false,
        remainingAttempts: 0
      };
    }

    // Verify OTP
    const isValid = this.verifyOTPCode(code, otp.hashedCode);

    // Increment attempts
    await this.emailOTPRepository.incrementAttempts(otp.id);

    if (!isValid) {
      const remainingAttempts = this.config.maxAttempts - otp.attempts - 1;
      
      // Log failed attempt
      await this.auditLogger.log({
        action: 'otp_failed',
        email,
        purpose,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date()
      });

      return {
        success: false,
        isValid: false,
        isExpired: false,
        remainingAttempts
      };
    }

    // Mark OTP as used
    await this.emailOTPRepository.markAsUsed(otp.id);

    // Get or create user
    let user = await this.userRepository.findByEmail(email);
    
    if (!user && purpose === 'login') {
      // Auto-create user on first login
      user = await this.userRepository.create({
        email,
        emailVerified: true,
        authMethod: 'email'
      });
    }

    // Generate auth token
    let token: string | undefined;
    
    if (user && purpose === 'login') {
      token = await this.tokenService.generateTokenPair(user, {
        ipAddress: context.ipAddress,
        userAgent: context.userAgent
      });
    }

    // Log successful verification
    await this.auditLogger.log({
      action: 'otp_verified',
      email,
      purpose,
      userId: user?.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: new Date()
    });

    return {
      success: true,
      isValid: true,
      isExpired: false,
      remainingAttempts: this.config.maxAttempts,
      user,
      token
    };
  }

  // Send magic link
  async sendMagicLink(
    email: string,
    redirectTo?: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<{
    success: boolean;
    expiresAt: Date;
  }> {
    if (!this.config.allowMagicLinks) {
      throw new Error('Magic links are disabled');
    }

    // Rate limiting check
    const rateLimit = await this.checkRateLimit(email, 'magic_link');
    
    if (!rateLimit.allowed) {
      throw new RateLimitError(
        'Too many magic link requests',
        rateLimit.resetAt
      );
    }

    // Generate magic link token
    const token = randomBytes(32).toString('hex');
    const expiresAt = addMinutes(new Date(), this.config.magicLinkExpiry);

    // Store magic link
    const magicLink: MagicLink = {
      id: randomBytes(16).toString('hex'),
      email,
      token,
      expiresAt,
      used: false,
      redirectTo,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent
    };

    await this.magicLinkRepository.save(magicLink);

    // Generate magic link URL
    const magicLinkUrl = this.generateMagicLinkUrl(token, redirectTo);

    // Send email with magic link
    await this.sendMagicLinkEmail(email, magicLinkUrl);

    // Log magic link sent
    await this.auditLogger.log({
      action: 'magic_link_sent',
      email,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: new Date()
    });

    return {
      success: true,
      expiresAt
    };
  }

  // Verify magic link
  async verifyMagicLink(
    token: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
    } = {}
  ): Promise<{
    success: boolean;
    isValid: boolean;
    isExpired: boolean;
    email?: string;
    redirectTo?: string;
    user?: User;
    authToken?: string;
  }> {
    const magicLink = await this.magicLinkRepository.findByToken(token);
    
    if (!magicLink) {
      return {
        success: false,
        isValid: false,
        isExpired: false
      };
    }

    // Check if magic link is expired
    if (isAfter(new Date(), magicLink.expiresAt)) {
      await this.magicLinkRepository.markAsExpired(magicLink.id);
      
      return {
        success: false,
        isValid: false,
        isExpired: true,
        email: magicLink.email
      };
    }

    // Check if magic link was already used
    if (magicLink.used) {
      return {
        success: false,
        isValid: false,
        isExpired: false,
        email: magicLink.email
      };
    }

    // Mark as used
    await this.magicLinkRepository.markAsUsed(magicLink.id);

    // Get or create user
    let user = await this.userRepository.findByEmail(magicLink.email);
    
    if (!user) {
      user = await this.userRepository.create({
        email: magicLink.email,
        emailVerified: true,
        authMethod: 'magic_link'
      });
    }

    // Generate auth token
    const authToken = await this.tokenService.generateTokenPair(user, {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent
    });

    // Log successful magic link
    await this.auditLogger.log({
      action: 'magic_link_used',
      email: magicLink.email,
      userId: user.id,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: new Date()
    });

    return {
      success: true,
      isValid: true,
      isExpired: false,
      email: magicLink.email,
      redirectTo: magicLink.redirectTo,
      user,
      authToken
    };
  }

  // Private helper methods
  private generateOTP(): string {
    // Generate numeric OTP
    const min = Math.pow(10, this.config.otpLength - 1);
    const max = Math.pow(10, this.config.otpLength) - 1;
    
    return randomInt(min, max).toString();
  }

  private hashOTP(otp: string): string {
    return createHash('sha256').update(otp).digest('hex');
  }

  private verifyOTPCode(code: string, hashedCode: string): boolean {
    const hash = this.hashOTP(code);
    return timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(hashedCode, 'hex')
    );
  }

  private async checkRateLimit(
    email: string,
    purpose: string
  ): Promise<{ allowed: boolean; resetAt?: Date }> {
    const key = `rate_limit:email_auth:${email}:${purpose}`;
    const attempts = await this.redis.get(key);
    
    if (!attempts) {
      await this.redis.setex(key, this.config.rateLimitWindow * 60, '1');
      return { allowed: true };
    }

    const count = parseInt(attempts, 10);
    
    if (count >= 5) { // 5 attempts per window
      const ttl = await this.redis.ttl(key);
      return {
        allowed: false,
        resetAt: new Date(Date.now() + ttl * 1000)
      };
    }

    await this.redis.incr(key);
    return { allowed: true };
  }

  private async cleanupOldOTPs(
    email: string,
    purpose: string
  ): Promise<void> {
    // Delete OTPs older than expiry time
    const cutoff = new Date(Date.now() - this.config.otpExpiry * 60 * 1000);
    await this.emailOTPRepository.deleteOld(email, purpose, cutoff);
  }

  private async sendEmail(
    email: string,
    otp: string,
    purpose: string
  ): Promise<void> {
    let subject: string;
    let template: string;

    switch (purpose) {
      case 'login':
        subject = 'Your Login Code';
        template = 'login-otp';
        break;
      case 'verification':
        subject = 'Verify Your Email';
        template = 'verification-otp';
        break;
      case 'password_reset':
        subject = 'Reset Your Password';
        template = 'password-reset-otp';
        break;
      default:
        subject = 'Your Verification Code';
        template = 'generic-otp';
    }

    await this.resend.emails.send({
      from: process.env.EMAIL_FROM!,
      to: email,
      subject,
      html: this.generateEmailTemplate(template, { otp }),
      headers: {
        'X-OTP-Purpose': purpose
      }
    });
  }

  private async sendMagicLinkEmail(
    email: string,
    magicLinkUrl: string
  ): Promise<void> {
    await this.resend.emails.send({
      from: process.env.EMAIL_FROM!,
      to: email,
      subject: 'Your Magic Link',
      html: this.generateMagicLinkTemplate(magicLinkUrl)
    });
  }

  private generateMagicLinkUrl(token: string, redirectTo?: string): string {
    const baseUrl = process.env.APP_URL;
    const url = new URL('/auth/magic-link', baseUrl);
    
    url.searchParams.set('token', token);
    
    if (redirectTo) {
      url.searchParams.set('redirect_to', redirectTo);
    }

    return url.toString();
  }

  private generateEmailTemplate(template: string, data: any): string {
    // Implement email template generation
    // This could use a templating engine like Handlebars or EJS
    switch (template) {
      case 'login-otp':
        return `
          <h1>Your Login Code</h1>
          <p>Use the following code to log in:</p>
          <h2>${data.otp}</h2>
          <p>This code will expire in ${this.config.otpExpiry} minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
        `;
      default:
        return `
          <h1>Your Verification Code</h1>
          <p>Use the following code to verify your email:</p>
          <h2>${data.otp}</h2>
          <p>This code will expire in ${this.config.otpExpiry} minutes.</p>
        `;
    }
  }

  private generateMagicLinkTemplate(magicLinkUrl: string): string {
    return `
      <h1>Your Magic Link</h1>
      <p>Click the link below to log in:</p>
      <p><a href="${magicLinkUrl}">Log In</a></p>
      <p>This link will expire in ${this.config.magicLinkExpiry} minutes.</p>
      <p>If you didn't request this link, please ignore this email.</p>
    `;
  }
}
```

## Secure Cookie Flags

### 🔐 Comprehensive Cookie Security

```typescript
// services/cookie-security.service.ts
import { Request, Response } from 'express';
import { randomBytes, createHash } from 'crypto';

export interface CookieSecurityConfig {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
  partitioned?: boolean;
  priority?: 'low' | 'medium' | 'high';
  // Additional security features
  encrypt: boolean;
  sign: boolean;
  encoding: 'json' | 'base64' | 'hex';
  compression: boolean;
}

export class CookieSecurityService {
  private readonly defaultConfig: CookieSecurityConfig = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    domain: process.env.COOKIE_DOMAIN,
    partitioned: true, // CHIPS: Partitioned cookies
    priority: 'high',
    encrypt: true,
    sign: true,
    encoding: 'json',
    compression: false
  };

  private readonly encryptionKey: Buffer;
  private readonly signingKey: Buffer;

  constructor() {
    // Generate keys from environment or derive from secret
    this.encryptionKey = this.deriveKey(process.env.COOKIE_ENCRYPTION_SECRET!, 'encryption');
    this.signingKey = this.deriveKey(process.env.COOKIE_SIGNING_SECRET!, 'signing');
  }

  // Set secure cookie
  setSecureCookie(
    res: Response,
    name: string,
    value: any,
    config: Partial<CookieSecurityConfig> = {}
  ): void {
    const finalConfig = { ...this.defaultConfig, ...config };
    
    // Prepare cookie value
    let cookieValue: string;
    
    if (finalConfig.encoding === 'json') {
      cookieValue = JSON.stringify(value);
    } else {
      cookieValue = String(value);
    }

    // Compress if enabled
    if (finalConfig.compression) {
      cookieValue = this.compress(cookieValue);
    }

    // Encrypt if enabled
    if (finalConfig.encrypt) {
      cookieValue = this.encrypt(cookieValue);
    }

    // Sign if enabled
    if (finalConfig.sign) {
      const signature = this.sign(cookieValue);
      cookieValue = `${cookieValue}.${signature}`;
    }

    // Encode for URL safety
    cookieValue = Buffer.from(cookieValue).toString('base64url');

    // Set cookie with security headers
    const cookieOptions: any = {
      httpOnly: finalConfig.httpOnly,
      secure: finalConfig.secure,
      sameSite: finalConfig.sameSite,
      path: finalConfig.path,
      domain: finalConfig.domain
    };

    if (finalConfig.maxAge) {
      cookieOptions.maxAge = finalConfig.maxAge * 1000;
    }

    if (finalConfig.expires) {
      cookieOptions.expires = finalConfig.expires;
    }

    // Set Partitioned attribute (CHIPS)
    if (finalConfig.partitioned) {
      cookieOptions.partitioned = true;
    }

    // Set Priority attribute
    if (finalConfig.priority) {
      // Note: Priority attribute is not yet widely supported
      // cookieOptions.priority = finalConfig.priority;
    }

    res.cookie(name, cookieValue, cookieOptions);

    // Set additional security headers
    this.setCookieSecurityHeaders(res);
  }

  // Get and verify secure cookie
  getSecureCookie(
    req: Request,
    name: string,
    config: Partial<CookieSecurityConfig> = {}
  ): any | null {
    const finalConfig = { ...this.defaultConfig, ...config };
    const cookieValue = req.cookies[name];

    if (!cookieValue) {
      return null;
    }

    try {
      // Decode from base64url
      let decodedValue = Buffer.from(cookieValue, 'base64url').toString('utf8');

      // Split value and signature
      const [value, signature] = decodedValue.split('.');

      // Verify signature if enabled
      if (finalConfig.sign && signature) {
        const expectedSignature = this.sign(value);
        
        if (!timingSafeEqual(
          Buffer.from(signature, 'hex'),
          Buffer.from(expectedSignature, 'hex')
        )) {
          // Log tampering attempt
          this.logTamperingAttempt(req, name);
          return null;
        }
      }

      let finalValue = value;

      // Decrypt if enabled
      if (finalConfig.encrypt) {
        finalValue = this.decrypt(finalValue);
      }

      // Decompress if enabled
      if (finalConfig.compression) {
        finalValue = this.decompress(finalValue);
      }

      // Parse based on encoding
      if (finalConfig.encoding === 'json') {
        return JSON.parse(finalValue);
      }

      return finalValue;
    } catch (error) {
      // Log parsing error
      this.logParsingError(req, name, error);
      return null;
    }
  }

  // Clear secure cookie
  clearSecureCookie(
    res: Response,
    name: string,
    config: Partial<CookieSecurityConfig> = {}
  ): void {
    const finalConfig = { ...this.defaultConfig, ...config };
    
    res.clearCookie(name, {
      httpOnly: finalConfig.httpOnly,
      secure: finalConfig.secure,
      sameSite: finalConfig.sameSite,
      path: finalConfig.path,
      domain: finalConfig.domain
    });
  }

  // Set multiple cookies with same security settings
  setSecureCookies(
    res: Response,
    cookies: Record<string, any>,
    config: Partial<CookieSecurityConfig> = {}
  ): void {
    for (const [name, value] of Object.entries(cookies)) {
      this.setSecureCookie(res, name, value, config);
    }
  }

  // Generate cookie attributes for Content Security Policy
  generateCSPCookieAttributes(): string {
    const attributes = [
      'Secure',
      'HttpOnly',
      'SameSite=Strict',
      'Path=/'
    ];

    if (this.defaultConfig.partitioned) {
      attributes.push('Partitioned');
    }

    return attributes.join('; ');
  }

  // Implement double submit cookie pattern for CSRF protection
  setCSRFCookie(
    res: Response,
    req: Request,
    config: Partial<CookieSecurityConfig> = {}
  ): string {
    const csrfToken = randomBytes(32).toString('hex');
    
    // Set HTTP-only cookie
    this.setSecureCookie(res, 'csrf_token', csrfToken, {
      ...config,
      httpOnly: true,
      sameSite: 'strict'
    });

    // Also set in response header for SPA to read
    res.setHeader('X-CSRF-Token', csrfToken);

    return csrfToken;
  }

  // Verify CSRF token
  verifyCSRFToken(req: Request): boolean {
    const cookieToken = this.getSecureCookie(req, 'csrf_token');
    const headerToken = req.headers['x-csrf-token'] || req.body?.csrfToken;

    if (!cookieToken || !headerToken) {
      return false;
    }

    return timingSafeEqual(
      Buffer.from(cookieToken),
      Buffer.from(headerToken)
    );
  }

  // Implement cookie prefixing (RFC 6265bis)
  setPrefixedCookie(
    res: Response,
    name: string,
    value: any,
    prefix: '__Host-' | '__Secure-',
    config: Partial<CookieSecurityConfig> = {}
  ): void {
    const prefixedName = `${prefix}${name}`;
    
    this.setSecureCookie(res, prefixedName, value, {
      ...config,
      secure: true,
      ...(prefix === '__Host-' && {
        domain: undefined, // __Host- cookies must not have Domain attribute
        path: '/' // Must have Path=/
      })
    });
  }

  // Private helper methods
  private deriveKey(secret: string, purpose: string): Buffer {
    return createHash('sha256')
      .update(`${secret}:${purpose}:${process.env.APP_KEY || ''}`)
      .digest();
  }

  private encrypt(data: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([iv, tag, encrypted]).toString('base64');
  }

  private decrypt(encrypted: string): string {
    const buffer = Buffer.from(encrypted, 'base64');
    
    const iv = buffer.slice(0, 16);
    const tag = buffer.slice(16, 32);
    const data = buffer.slice(32);
    
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(tag);
    
    return decipher.update(data) + decipher.final('utf8');
  }

  private sign(data: string): string {
    return createHmac('sha256', this.signingKey)
      .update(data)
      .digest('hex');
  }

  private compress(data: string): string {
    // Implement compression (e.g., using zlib)
    const compressed = gzipSync(data);
    return compressed.toString('base64');
  }

  private decompress(data: string): string {
    const buffer = Buffer.from(data, 'base64');
    return gunzipSync(buffer).toString('utf8');
  }

  private setCookieSecurityHeaders(res: Response): void {
    // Set security headers related to cookies
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Content Security Policy with cookie directives
    const csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "media-src 'self'",
      "frame-src 'none'",
      "sandbox allow-forms allow-same-origin allow-scripts",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "block-all-mixed-content",
      "upgrade-insecure-requests"
    ].join('; ');

    res.setHeader('Content-Security-Policy', csp);
    
    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions Policy
    res.setHeader('Permissions-Policy', [
      'geolocation=()',
      'microphone=()',
      'camera=()',
      'payment=()'
    ].join(', '));
  }

  private logTamperingAttempt(req: Request, cookieName: string): void {
    this.auditLogger.warn({
      action: 'cookie_tampering',
      cookieName,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date()
    });
  }

  private logParsingError(
    req: Request,
    cookieName: string,
    error: Error
  ): void {
    this.auditLogger.error({
      action: 'cookie_parsing_error',
      cookieName,
      error: error.message,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date()
    });
  }
}
```

### 🛡️ Advanced Cookie Protection

```typescript
// middleware/cookie-protection.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { CookieSecurityService } from '@/services/cookie-security.service';

export const cookieProtectionMiddleware = (
  cookieSecurityService: CookieSecurityService
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // 1. Check for suspicious cookie patterns
    this.detectSuspiciousCookies(req);

    // 2. Implement cookie freshness
    this.checkCookieFreshness(req, res);

    // 3. Set secure cookie headers
    this.setCookieHeaders(res);

    // 4. Validate cookie attributes
    this.validateCookieAttributes(req);

    next();
  };
};

// Cookie theft detection
export const cookieTheftDetection = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies.session_id;
    
    if (!sessionId) {
      return next();
    }

    // Get stored session data
    const session = await sessionService.getSession(sessionId);
    
    if (!session) {
      return next();
    }

    // Check for suspicious changes
    const suspiciousFlags: string[] = [];

    // IP address change detection
    if (session.ipAddress && session.ipAddress !== req.ip) {
      suspiciousFlags.push('ip_mismatch');
      
      // Calculate geographic distance if possible
      const distance = await this.calculateGeoDistance(
        session.ipAddress,
        req.ip
      );
      
      if (distance > 500) { // More than 500km
        suspiciousFlags.push('geographic_anomaly');
      }
    }

    // User agent change detection
    const currentUserAgent = req.get('user-agent');
    if (session.userAgent && session.userAgent !== currentUserAgent) {
      suspiciousFlags.push('user_agent_mismatch');
    }

    // Device fingerprint change
    const deviceFingerprint = this.generateDeviceFingerprint(req);
    if (session.deviceFingerprint && session.deviceFingerprint !== deviceFingerprint) {
      suspiciousFlags.push('device_fingerprint_mismatch');
    }

    // Login pattern anomaly detection
    if (await this.isLoginPatternAnomaly(session.userId, req)) {
      suspiciousFlags.push('login_pattern_anomaly');
    }

    // Take action based on suspicious flags
    if (suspiciousFlags.length > 0) {
      await this.handleSuspiciousActivity(
        session.userId,
        sessionId,
        suspiciousFlags,
        req
      );

      // For high-risk anomalies, require re-authentication
      if (suspiciousFlags.includes('geographic_anomaly') || 
          suspiciousFlags.includes('device_fingerprint_mismatch')) {
        
        // Clear session and require re-login
        res.clearCookie('session_id');
        
        return res.status(401).json({
          error: 'Suspicious activity detected',
          action: 'reauthentication_required'
        });
      }
    }

    next();
  };
};

// Cookie consent management
export const cookieConsentMiddleware = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Check for GDPR/CCPA compliance
    const consent = req.cookies.consent;
    
    if (!consent && this.requiresConsent(req)) {
      // Track pre-consent (anonymous) user
      const anonymousId = this.generateAnonymousId(req);
      res.cookie('anonymous_id', anonymousId, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: 365 * 24 * 60 * 60 * 1000 // 1 year
      });

      // Set do-not-track headers for compliant tracking
      res.setHeader('Tk', 'N'); // Tracking Status value 'N' for non-compliance
    }

    // Add consent check to response locals
    res.locals.hasConsent = this.hasValidConsent(consent);

    next();
  };
};

// HTTP-only cookie enforcement
export const httpOnlyCookieEnforcement = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Check for JavaScript cookie access attempts
    const cookies = Object.keys(req.cookies);
    
    for (const cookieName of cookies) {
      if (cookieName.startsWith('js_')) {
        // Log potential XSS attempt
        this.logSecurityEvent({
          type: 'potential_xss',
          cookieName,
          ipAddress: req.ip,
          userAgent: req.get('user-agent')
        });

        // Clear the potentially dangerous cookie
        res.clearCookie(cookieName);
      }
    }

    // Set headers to prevent cookie theft via XSS
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    next();
  };
};

// Subdomain cookie isolation
export const subdomainCookieIsolation = (
  allowedSubdomains: string[] = []
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const hostname = req.hostname;
    const parts = hostname.split('.');
    
    if (parts.length > 2) {
      const subdomain = parts[0];
      
      // Check if subdomain is allowed
      if (!allowedSubdomains.includes(subdomain) && subdomain !== 'www') {
        // Isolate cookies to specific subdomain
        res.locals.cookieDomain = `.${parts.slice(-2).join('.')}`;
        
        // Clear any cookies set on wrong subdomain
        this.clearCrossSubdomainCookies(req, res, subdomain);
      }
    }

    next();
  };
};

// Cookie lifetime management
export const cookieLifetimeManagement = (
  maxLifetime: number = 30 * 24 * 60 * 60 * 1000 // 30 days
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const cookies = req.cookies;
    const now = Date.now();

    for (const [name, value] of Object.entries(cookies)) {
      // Check for timestamp in cookie value
      if (typeof value === 'string' && value.includes('|')) {
        const [cookieValue, timestamp] = value.split('|');
        const cookieAge = now - parseInt(timestamp, 10);

        if (cookieAge > maxLifetime) {
          // Cookie is too old, clear it
          res.clearCookie(name);
          
          // Log for audit
          this.logSecurityEvent({
            type: 'cookie_expired',
            cookieName: name,
            age: cookieAge
          });
        }
      }
    }

    next();
  };
};

// Private helper methods
private detectSuspiciousCookies(req: Request): void {
  const suspiciousPatterns = [
    /\.\.\//, // Directory traversal
    /<script>/i, // Script tags
    /javascript:/i, // JavaScript protocol
    /on\w+=/i, // Event handlers
    /eval\(/i, // eval calls
    /document\.cookie/i // Cookie access
  ];

  for (const [name, value] of Object.entries(req.cookies)) {
    const cookieString = `${name}=${value}`;
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(cookieString)) {
        this.logSecurityEvent({
          type: 'suspicious_cookie',
          cookieName: name,
          pattern: pattern.source,
          ipAddress: req.ip,
          userAgent: req.get('user-agent')
        });
        
        // Clear the suspicious cookie
        req.clearCookie(name);
        break;
      }
    }
  }
}

private checkCookieFreshness(req: Request, res: Response): void {
  const sessionCookie = req.cookies.session_id;
  
  if (sessionCookie) {
    // Add freshness timestamp
    const freshness = Date.now();
    const freshCookie = `${sessionCookie}|${freshness}`;
    
    // Update cookie with freshness timestamp
    res.cookie('session_freshness', freshness, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
  }
}

private setCookieHeaders(res: Response): void {
  // Set cookie-related security headers
  res.setHeader('Set-Cookie', [
    // Example of secure cookie attributes
    'session_id=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400',
    'csrf_token=xyz789; Secure; HttpOnly; SameSite=Strict; Path=/',
    
    // Partitioned cookie example
    '__Host-session=partitioned; Secure; HttpOnly; SameSite=Strict; Path=/; Partitioned'
  ].join(', '));
}

private validateCookieAttributes(req: Request): void {
  // Validate that cookies have proper attributes
  const cookieHeader = req.headers.cookie;
  
  if (cookieHeader) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    
    for (const cookie of cookies) {
      // Check for missing secure flag on HTTPS
      if (req.secure && !cookie.toLowerCase().includes('secure')) {
        this.logSecurityEvent({
          type: 'insecure_cookie',
          cookie,
          ipAddress: req.ip
        });
      }
      
      // Check for missing HttpOnly flag on sensitive cookies
      const sensitiveCookies = ['session', 'token', 'auth'];
      const [name] = cookie.split('=');
      
      if (sensitiveCookies.some(sc => name.toLowerCase().includes(sc)) && 
          !cookie.toLowerCase().includes('httponly')) {
        this.logSecurityEvent({
          type: 'non_httponly_cookie',
          cookieName: name,
          ipAddress: req.ip
        });
      }
    }
  }
}

private generateDeviceFingerprint(req: Request): string {
  const components = [
    req.get('user-agent'),
    req.get('accept-language'),
    req.get('accept-encoding'),
    req.ip
  ].filter(Boolean).join('|');
  
  return createHash('sha256').update(components).digest('hex');
}

private async calculateGeoDistance(ip1: string, ip2: string): Promise<number> {
  // Implement geo distance calculation using IP geolocation
  // This is a simplified example
  return 0;
}

private async isLoginPatternAnomaly(
  userId: string,
  req: Request
): Promise<boolean> {
  // Check login patterns for anomalies
  const recentLogins = await this.auditLogger.getRecentLogins(userId, 10);
  
  if (recentLogins.length === 0) {
    return false;
  }

  // Check time between logins
  const now = new Date();
  const lastLogin = recentLogins[0].timestamp;
  const timeDiff = now.getTime() - lastLogin.getTime();
  
  // If login from different location within 5 minutes
  if (timeDiff < 5 * 60 * 1000) {
    const locations = new Set(recentLogins.map(l => l.ipAddress));
    if (locations.size > 1 && !locations.has(req.ip)) {
      return true;
    }
  }

  return false;
}

private async handleSuspiciousActivity(
  userId: string,
  sessionId: string,
  flags: string[],
  req: Request
): Promise<void> {
  // Log suspicious activity
  await this.auditLogger.log({
    userId,
    action: 'suspicious_activity',
    flags,
    ipAddress: req.ip,
    userAgent: req.get('user-agent'),
    sessionId,
    timestamp: new Date()
  });

  // Send security notification
  await this.notificationService.sendSecurityAlert(userId, {
    type: 'suspicious_activity',
    flags,
    ipAddress: req.ip,
    timestamp: new Date()
  });

  // For critical flags, require additional verification
  if (flags.includes('geographic_anomaly')) {
    await this.twoFactorService.requireVerification(userId, 'email');
  }
}

private requiresConsent(req: Request): boolean {
  // Check if user is from GDPR/CCPA region
  const country = req.headers['cf-ipcountry'] || 
                  req.headers['x-country-code'] ||
                  'US';
  
  const gdprCountries = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI',
                         'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU',
                         'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
                         'GB'];
  
  const ccpaStates = ['CA', 'CO', 'VA', 'UT'];
  
  return gdprCountries.includes(country) || ccpaStates.includes(country);
}

private hasValidConsent(consent: any): boolean {
  if (!consent) {
    return false;
  }

  try {
    const parsed = JSON.parse(consent);
    return parsed.necessary === true && 
           new Date(parsed.timestamp).getTime() > Date.now() - (365 * 24 * 60 * 60 * 1000);
  } catch {
    return false;
  }
}

private clearCrossSubdomainCookies(
  req: Request,
  res: Response,
  currentSubdomain: string
): void {
  const cookies = req.cookies;
  
  for (const [name, value] of Object.entries(cookies)) {
    // Check if cookie was set for different subdomain
    if (value && typeof value === 'string' && value.includes('@')) {
      const [cookieValue, domain] = value.split('@');
      
      if (domain && domain !== currentSubdomain) {
        res.clearCookie(name, {
          domain: `.${domain}.${req.hostname.split('.').slice(-2).join('.')}`
        });
      }
    }
  }
}

private generateAnonymousId(req: Request): string {
  const components = [
    req.ip,
    req.get('user-agent'),
    Date.now().toString()
  ].join('|');
  
  return createHash('sha256').update(components).digest('hex').slice(0, 16);
}

private logSecurityEvent(event: any): void {
  // Implement security event logging
  console.log('Security Event:', event);
}
```

## Refresh Token Rotation

### 🔄 Advanced Refresh Token Patterns

```typescript
// services/refresh-token-rotation.service.ts
import { Redis } from 'ioredis';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { addDays, isBefore, isAfter } from 'date-fns';

export interface RefreshTokenRotationConfig {
  rotationEnabled: boolean;
  reuseDetection: boolean;
  gracePeriod: number; // seconds
  familyLimit: number;
  automaticReuseResponse: 'revoke_all' | 'notify' | 'ignore';
}

export interface RefreshTokenFamily {
  id: string;
  userId: string;
  currentTokenId: string;
  previousTokenIds: string[];
  createdAt: Date;
  lastRotatedAt: Date;
  rotationCount: number;
  revoked: boolean;
  revokedAt?: Date;
}

export class RefreshTokenRotationService {
  private readonly config: RefreshTokenRotationConfig = {
    rotationEnabled: true,
    reuseDetection: true,
    gracePeriod: 60, // 1 minute grace period
    familyLimit: 5,
    automaticReuseResponse: 'revoke_all'
  };

  constructor(
    private redis: Redis,
    private refreshTokenRepository: RefreshTokenRepository
  ) {}

  // Issue new refresh token with rotation
  async issueRefreshToken(
    userId: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
      deviceInfo?: DeviceInfo;
    }
  ): Promise<{
    token: string;
    familyId: string;
    tokenId: string;
    expiresAt: Date;
  }> {
    // Generate token and family
    const token = randomBytes(32).toString('hex');
    const tokenId = randomBytes(16).toString('hex');
    const familyId = randomBytes(16).toString('hex');
    
    const expiresAt = addDays(new Date(), 30);

    // Hash token for storage
    const tokenHash = this.hashToken(token);

    // Check for existing token family
    let family = await this.getActiveTokenFamily(userId);
    
    if (!family || !this.config.rotationEnabled) {
      // Create new token family
      family = await this.createTokenFamily(userId, familyId, tokenId);
    } else {
      // Rotate within existing family
      await this.rotateTokenFamily(family, tokenId);
    }

    // Store refresh token
    await this.refreshTokenRepository.create({
      id: tokenId,
      familyId: family.id,
      userId,
      tokenHash,
      deviceInfo: context.deviceInfo,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      issuedAt: new Date(),
      expiresAt,
      revoked: false,
      lastUsedAt: new Date()
    });

    // Store in Redis for fast validation
    await this.redis.setex(
      `refresh_token:${tokenHash}`,
      30 * 24 * 60 * 60, // 30 days
      JSON.stringify({
        tokenId,
        familyId: family.id,
        userId,
        issuedAt: new Date().toISOString()
      })
    );

    return {
      token,
      familyId: family.id,
      tokenId,
      expiresAt
    };
  }

  // Validate and rotate refresh token
  async validateAndRotate(
    refreshToken: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
    }
  ): Promise<{
    valid: boolean;
    newToken?: string;
    accessToken?: string;
    reason?: string;
    familyRevoked?: boolean;
  }> {
    const tokenHash = this.hashToken(refreshToken);

    // Check Redis cache first
    const cached = await this.redis.get(`refresh_token:${tokenHash}`);
    
    if (cached) {
      const tokenData = JSON.parse(cached);
      
      // Check if token is expired
      if (isAfter(new Date(), new Date(tokenData.expiresAt))) {
        await this.revokeToken(tokenData.tokenId);
        return { valid: false, reason: 'token_expired' };
      }
    }

    // Get token from database
    const tokenRecord = await this.refreshTokenRepository.findByHash(tokenHash);
    
    if (!tokenRecord) {
      return { valid: false, reason: 'token_not_found' };
    }

    // Check if token is revoked
    if (tokenRecord.revoked) {
      // Check for token reuse
      if (this.config.reuseDetection && tokenRecord.lastUsedAt) {
        const reuseDetected = await this.detectTokenReuse(tokenRecord, context);
        
        if (reuseDetected) {
          return await this.handleTokenReuse(tokenRecord);
        }
      }
      
      return { valid: false, reason: 'token_revoked' };
    }

    // Check if token is expired
    if (isAfter(new Date(), tokenRecord.expiresAt)) {
      await this.revokeToken(tokenRecord.id);
      return { valid: false, reason: 'token_expired' };
    }

    // Check grace period for recently rotated tokens
    if (tokenRecord.replacedAt) {
      const gracePeriodEnd = new Date(
        tokenRecord.replacedAt.getTime() + (this.config.gracePeriod * 1000)
      );
      
      if (isAfter(new Date(), gracePeriodEnd)) {
        await this.revokeToken(tokenRecord.id);
        return { valid: false, reason: 'grace_period_expired' };
      }
    }

    // Update last used timestamp
    tokenRecord.lastUsedAt = new Date();
    await this.refreshTokenRepository.update(tokenRecord.id, {
      lastUsedAt: tokenRecord.lastUsedAt
    });

    // Get token family
    const family = await this.refreshTokenFamilyRepository.findById(
      tokenRecord.familyId
    );

    if (!family) {
      return { valid: false, reason: 'token_family_not_found' };
    }

    // Check if family is revoked
    if (family.revoked) {
      return {
        valid: false,
        reason: 'token_family_revoked',
        familyRevoked: true
      };
    }

    // Rotate token if enabled
    let newToken: string | undefined;
    
    if (this.config.rotationEnabled) {
      newToken = await this.rotateToken(tokenRecord, family, context);
    }

    // Generate access token
    const user = await this.userRepository.findById(tokenRecord.userId);
    
    if (!user) {
      return { valid: false, reason: 'user_not_found' };
    }

    const accessToken = await this.jwtService.createAccessToken({
      sub: user.id,
      email: user.email,
      role: user.role,
      permissions: user.permissions
    });

    return {
      valid: true,
      newToken,
      accessToken
    };
  }

  // Revoke token and its family
  async revokeTokenAndFamily(tokenId: string): Promise<void> {
    const token = await this.refreshTokenRepository.findById(tokenId);
    
    if (!token) {
      return;
    }

    // Revoke all tokens in the family
    await this.refreshTokenFamilyRepository.update(token.familyId, {
      revoked: true,
      revokedAt: new Date()
    });

    // Revoke all individual tokens
    await this.refreshTokenRepository.revokeByFamily(token.familyId);

    // Clear Redis cache
    const familyTokens = await this.refreshTokenRepository.findByFamily(
      token.familyId
    );
    
    for (const familyToken of familyTokens) {
      await this.redis.del(`refresh_token:${familyToken.tokenHash}`);
    }

    // Log revocation
    await this.auditLogger.log({
      userId: token.userId,
      action: 'token_family_revoked',
      tokenId,
      familyId: token.familyId,
      reason: 'security_breach',
      timestamp: new Date()
    });
  }

  // Detect token reuse
  private async detectTokenReuse(
    tokenRecord: RefreshTokenRecord,
    context: { ipAddress?: string; userAgent?: string }
  ): Promise<boolean> {
    // Check if token was used from different location/device
    if (tokenRecord.ipAddress && tokenRecord.ipAddress !== context.ipAddress) {
      return true;
    }

    if (tokenRecord.userAgent && tokenRecord.userAgent !== context.userAgent) {
      return true;
    }

    // Check if token was used after being marked as revoked
    if (tokenRecord.revokedAt && tokenRecord.lastUsedAt) {
      return isAfter(tokenRecord.lastUsedAt, tokenRecord.revokedAt);
    }

    return false;
  }

  // Handle token reuse detection
  private async handleTokenReuse(
    reusedToken: RefreshTokenRecord
  ): Promise<{
    valid: boolean;
    reason: string;
    familyRevoked: boolean;
  }> {
    // Log the reuse attempt
    await this.auditLogger.log({
      userId: reusedToken.userId,
      action: 'token_reuse_detected',
      tokenId: reusedToken.id,
      familyId: reusedToken.familyId,
      timestamp: new Date()
    });

    // Take action based on configuration
    switch (this.config.automaticReuseResponse) {
      case 'revoke_all':
        await this.revokeTokenAndFamily(reusedToken.id);
        return {
          valid: false,
          reason: 'token_reuse_detected',
          familyRevoked: true
        };
      
      case 'notify':
        await this.notificationService.sendSecurityAlert(
          reusedToken.userId,
          {
            type: 'token_reuse_detected',
            tokenId: reusedToken.id,
            timestamp: new Date()
          }
        );
        
        return {
          valid: false,
          reason: 'token_reuse_detected',
          familyRevoked: false
        };
      
      case 'ignore':
      default:
        return {
          valid: false,
          reason: 'token_reuse_detected',
          familyRevoked: false
        };
    }
  }

  // Rotate refresh token
  private async rotateToken(
    oldToken: RefreshTokenRecord,
    family: RefreshTokenFamily,
    context: { ipAddress?: string; userAgent?: string }
  ): Promise<string> {
    // Generate new token
    const newToken = randomBytes(32).toString('hex');
    const newTokenId = randomBytes(16).toString('hex');
    const newTokenHash = this.hashToken(newToken);

    // Create new token record
    const newTokenRecord: RefreshTokenRecord = {
      id: newTokenId,
      familyId: family.id,
      userId: oldToken.userId,
      tokenHash: newTokenHash,
      deviceInfo: oldToken.deviceInfo,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      issuedAt: new Date(),
      expiresAt: addDays(new Date(), 30),
      revoked: false,
      lastUsedAt: new Date(),
      replacedTokenId: oldToken.id
    };

    await this.refreshTokenRepository.create(newTokenRecord);

    // Mark old token as replaced
    await this.refreshTokenRepository.update(oldToken.id, {
      replacedAt: new Date(),
      replacedByTokenId: newTokenId
    });

    // Update token family
    family.currentTokenId = newTokenId;
    family.previousTokenIds.push(oldToken.id);
    family.lastRotatedAt = new Date();
    family.rotationCount += 1;

    // Limit family size
    if (family.previousTokenIds.length > this.config.familyLimit) {
      const oldestTokenId = family.previousTokenIds.shift();
      if (oldestTokenId) {
        await this.revokeToken(oldestTokenId);
      }
    }

    await this.refreshTokenFamilyRepository.update(family.id, family);

    // Store in Redis
    await this.redis.setex(
      `refresh_token:${newTokenHash}`,
      30 * 24 * 60 * 60,
      JSON.stringify({
        tokenId: newTokenId,
        familyId: family.id,
        userId: oldToken.userId,
        issuedAt: new Date().toISOString()
      })
    );

    // Remove old token from Redis after grace period
    setTimeout(async () => {
      await this.redis.del(`refresh_token:${oldToken.tokenHash}`);
    }, this.config.gracePeriod * 1000);

    return newToken;
  }

  // Create new token family
  private async createTokenFamily(
    userId: string,
    familyId: string,
    tokenId: string
  ): Promise<RefreshTokenFamily> {
    const family: RefreshTokenFamily = {
      id: familyId,
      userId,
      currentTokenId: tokenId,
      previousTokenIds: [],
      createdAt: new Date(),
      lastRotatedAt: new Date(),
      rotationCount: 1,
      revoked: false
    };

    await this.refreshTokenFamilyRepository.create(family);
    return family;
  }

  // Rotate within existing family
  private async rotateTokenFamily(
    family: RefreshTokenFamily,
    newTokenId: string
  ): Promise<void> {
    family.currentTokenId = newTokenId;
    family.lastRotatedAt = new Date();
    family.rotationCount += 1;

    await this.refreshTokenFamilyRepository.update(family.id, family);
  }

  // Get active token family for user
  private async getActiveTokenFamily(userId: string): Promise<RefreshTokenFamily | null> {
    const families = await this.refreshTokenFamilyRepository.findByUser(userId);
    
    return families.find(f => !f.revoked) || null;
  }

  // Revoke single token
  private async revokeToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepository.update(tokenId, {
      revoked: true,
      revokedAt: new Date()
    });

    const token = await this.refreshTokenRepository.findById(tokenId);
    if (token) {
      await this.redis.del(`refresh_token:${token.tokenHash}`);
    }
  }

  // Hash token
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
```

### 🛡️ Refresh Token Security Middleware

```typescript
// middleware/refresh-token-security.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { RefreshTokenRotationService } from '@/services/refresh-token-rotation.service';

export const refreshTokenSecurityMiddleware = (
  rotationService: RefreshTokenRotationService
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // This middleware should be used on refresh token endpoint
    
    const refreshToken = req.body.refreshToken || 
                        req.cookies.refresh_token ||
                        req.headers['x-refresh-token'];

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    try {
      // Validate and rotate token
      const result = await rotationService.validateAndRotate(refreshToken, {
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });

      if (!result.valid) {
        // Handle different failure reasons
        switch (result.reason) {
          case 'token_reuse_detected':
            // Send security alert
            await securityService.alertTokenReuse(req.ip, result.familyRevoked);
            
            if (result.familyRevoked) {
              return res.status(401).json({
                error: 'Security violation detected',
                action: 'reauthentication_required'
              });
            }
            break;
          
          case 'token_family_revoked':
            return res.status(401).json({
              error: 'Session revoked due to security concerns',
              action: 'reauthentication_required'
            });
          
          default:
            return res.status(401).json({
              error: 'Invalid refresh token',
              reason: result.reason
            });
        }
      }

      // Attach new tokens to response
      if (result.newToken) {
        // Set new refresh token in HTTP-only cookie
        res.cookie('refresh_token', result.newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          path: '/api/auth/refresh'
        });
      }

      // Return new access token
      res.json({
        accessToken: result.accessToken,
        tokenType: 'Bearer',
        expiresIn: 15 * 60 // 15 minutes
      });
    } catch (error) {
      next(error);
    }
  };
};

// Device binding for refresh tokens
export const deviceBindingMiddleware = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deviceFingerprint = generateDeviceFingerprint(req);
    
    // Store device fingerprint in request
    req.deviceFingerprint = deviceFingerprint;

    // Check if refresh token endpoint
    if (req.path === '/api/auth/refresh') {
      const refreshToken = req.body.refreshToken || req.cookies.refresh_token;
      
      if (refreshToken) {
        // Verify device binding
        const isBound = await deviceBindingService.verifyDeviceBinding(
          refreshToken,
          deviceFingerprint
        );

        if (!isBound) {
          return res.status(401).json({
            error: 'Device binding violation',
            action: 'reauthentication_required'
          });
        }
      }
    }

    next();
  };
};

// Refresh token audit logging
export const refreshTokenAuditMiddleware = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const originalJson = res.json;
    const startTime = Date.now();

    res.json = function(body) {
      // Log refresh token usage
      if (req.path === '/api/auth/refresh') {
        const refreshToken = req.body.refreshToken || req.cookies.refresh_token;
        
        if (refreshToken) {
          const duration = Date.now() - startTime;
          
          auditLogger.log({
            action: 'refresh_token_used',
            success: res.statusCode < 400,
            duration,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            timestamp: new Date()
          }).catch(console.error);
        }
      }

      return originalJson.call(this, body);
    };

    next();
  };
};

// Rate limiting for refresh tokens
export const refreshTokenRateLimit = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.path !== '/api/auth/refresh') {
      return next();
    }

    const key = `rate_limit:refresh:${req.ip}`;
    const limit = 10; // 10 requests per hour
    const windowMs = 60 * 60 * 1000; // 1 hour

    try {
      const current = await redis.get(key);
      
      if (current && parseInt(current, 10) >= limit) {
        return res.status(429).json({
          error: 'Too many refresh requests',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      await redis.multi()
        .incr(key)
        .expire(key, Math.ceil(windowMs / 1000))
        .exec();
      
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Helper function to generate device fingerprint
function generateDeviceFingerprint(req: Request): string {
  const components = [
    req.get('user-agent'),
    req.get('accept-language'),
    req.get('accept-encoding'),
    req.get('sec-ch-ua'),
    req.get('sec-ch-ua-mobile'),
    req.get('sec-ch-ua-platform'),
    req.ip
  ].filter(Boolean).join('|');
  
  return createHash('sha256').update(components).digest('hex');
}
```

## Interview Questions

### 🔐 JWT Authentication

**Basic:**
1. What is JWT and what are its three parts?
2. How do you verify a JWT token in Express?
3. What's the difference between symmetric and asymmetric JWT signing?

**Advanced:**
4. Explain JWT token revocation strategies in a distributed system.
5. How would you implement JWT token refresh without compromising security?
6. What are the security considerations when storing JWTs in localStorage vs cookies?

**Senior Level:**
7. Design a JWT-based authentication system with key rotation and token introspection.
8. How would you prevent JWT replay attacks in a microservices architecture?
9. Explain the trade-offs between using JWTs vs session-based authentication.

### 🔄 Access Token + Refresh Token

**Basic:**
1. Why use both access and refresh tokens?
2. What are typical lifetimes for access vs refresh tokens?
3. How do you securely store refresh tokens?

**Advanced:**
4. Explain the refresh token rotation pattern and its security benefits.
5. How would you handle refresh token revocation across multiple devices?
6. What strategies would you use to detect refresh token theft?

**Senior Level:**
7. Design a token management system that supports offline access and device sync.
8. How would you implement token binding to prevent token misuse?
9. Explain how to handle token expiration during long-running operations.

### 🔐 Password Hashing

**Basic:**
1. Why shouldn't you store passwords in plain text?
2. What's the difference between hashing and encryption for passwords?
3. Why is bcrypt considered better than SHA-256 for password hashing?

**Advanced:**
4. Explain how Argon2 provides better security than bcrypt.
5. How would you implement password hashing with salting and peppering?
6. What are rainbow tables and how do salts prevent them?

**Senior Level:**
7. Design a password hashing system that can evolve with computational advances.
8. How would you handle password migration from weak to strong hash algorithms?
9. Explain timing attacks and how to prevent them in password verification.

### 🍪 Session Authentication

**Basic:**
1. How does session-based authentication differ from token-based?
2. What information should be stored in a session?
3. How do you prevent session fixation attacks?

**Advanced:**
4. Explain how to implement distributed sessions with Redis.
5. What are the security implications of session storage location?
6. How would you handle session expiration and renewal?

**Senior Level:**
7. Design a session management system with concurrent session limits.
8. How would you implement session migration during server maintenance?
9. Explain strategies for detecting and preventing session hijacking.

### 🔗 OAuth 2.0 & OpenID Connect

**Basic:**
1. What are the different OAuth 2.0 grant types and when to use each?
2. Explain the authorization code flow with PKCE.
3. What's the difference between OAuth 2.0 and OpenID Connect?

**Advanced:**
4. How would you implement OAuth 2.0 for a mobile app securely?
5. Explain token introspection and revocation endpoints.
6. What security considerations are there for OAuth redirect URIs?

**Senior Level:**
7. Design an OAuth 2.0 provider with support for multiple client types.
8. How would you implement federated identity with multiple identity providers?
9. Explain OAuth 2.0 threat model and mitigation strategies.

### 🏛️ Role-Based Access Control (RBAC)

**Basic:**
1. What's the difference between authentication and authorization?
2. Explain the principle of least privilege in RBAC.
3. How do roles differ from permissions?

**Advanced:**
4. How would you implement hierarchical roles with inheritance?
5. Explain attribute-based access control (ABAC) vs RBAC.
6. What strategies would you use for permission caching?

**Senior Level:**
7. Design an RBAC system that supports multi-tenancy.
8. How would you implement dynamic role assignment based on context?
9. Explain strategies for auditing and compliance in RBAC systems.

### 🔐 Two-Factor Authentication (2FA)

**Basic:**
1. What are the common 2FA methods and their security trade-offs?
2. How does TOTP work and why is it time-based?
3. What are backup codes and how should they be stored?

**Advanced:**
4. How would you implement 2FA with WebAuthn/FIDO2?
5. Explain the security considerations for SMS-based 2FA.
6. How do you handle 2FA recovery for locked-out users?

**Senior Level:**
7. Design a 2FA system that supports multiple methods and fallbacks.
8. How would you implement step-up authentication for sensitive operations?
9. Explain strategies for detecting and preventing 2FA bypass attacks.

### 📧 Email Login / OTP

**Basic:**
1. What are the security benefits of email-based authentication?
2. How do you prevent email OTP brute force attacks?
3. What's the difference between OTP and magic links?

**Advanced:**
4. How would you implement rate limiting for email OTP requests?
5. Explain strategies for preventing email OTP replay attacks.
6. How do you handle email deliverability issues in authentication?

**Senior Level:**
7. Design an email authentication system with automatic user provisioning.
8. How would you implement passwordless authentication across multiple devices?
9. Explain strategies for detecting and preventing email takeover attacks.

### 🛡️ Secure Cookie Flags

**Basic:**
1. What does the HttpOnly flag do and why is it important?
2. Explain the SameSite attribute and its different values.
3. When should you use the Secure flag for cookies?

**Advanced:**
4. How does the Partitioned attribute (CHIPS) improve privacy?
5. What are cookie prefixes (__Host-, __Secure-) and when to use them?
6. Explain strategies for preventing CSRF with cookies.

**Senior Level:**
7. Design a cookie security strategy for a multi-domain application.
8. How would you implement cookie consent management for GDPR/CCPA?
9. Explain strategies for detecting and preventing cookie theft.

### 🔄 Refresh Token Rotation

**Basic:**
1. What is refresh token rotation and why is it important?
2. How does rotation help detect token reuse?
3. What is a token family in rotation patterns?

**Advanced:**
4. Explain the grace period concept in token rotation.
5. How would you implement token family limits?
6. What strategies would you use for detecting token reuse?

**Senior Level:**
7. Design a refresh token system with automatic revocation on reuse detection.
8. How would you implement device binding for refresh tokens?
9. Explain strategies for handling token rotation in offline scenarios.

## Real-World Scenarios

### 🎯 Scenario 1: Financial Application Security Audit
**Situation:** You're the lead developer for a banking application undergoing a security audit. The auditors have identified several authentication vulnerabilities.

**Vulnerabilities Found:**
1. No rate limiting on login attempts
2. Weak password policy enforcement
3. JWTs stored in localStorage
4. No 2FA for sensitive operations
5. Session fixation vulnerability

**Tasks:**
1. Implement comprehensive rate limiting
2. Strengthen password policies
3. Migrate from localStorage to secure cookies
4. Add 2FA for money transfers
5. Fix session management issues

**Solution Implementation:**
```typescript
// 1. Rate limiting middleware
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.',
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `${req.ip}:${req.body.email}`
});

// 2. Password policy service
class BankingPasswordPolicy extends PasswordPolicyService {
  constructor() {
    super({
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      maxRepeatedChars: 2,
      blockCommonPasswords: true,
      blockSequentialChars: true,
      expiryDays: 90,
      historySize: 5
    });
  }
}

// 3. Secure cookie configuration
const cookieConfig = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  partitioned: true,
  domain: '.bank.example.com',
  path: '/',
  maxAge: 15 * 60 * 1000 // 15 minutes
};

// 4. 2FA for sensitive operations
const require2FA = (operation: string) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user.sub;
    const has2FA = await twoFactorService.isEnabled(userId);
    
    if (!has2FA && operation === 'money_transfer') {
      return res.status(403).json({
        error: '2FA required for money transfers',
        action: 'setup_2fa'
      });
    }
    
    if (has2FA && !req.session.twoFactorVerified) {
      return res.status(403).json({
        error: '2FA verification required',
        action: 'verify_2fa'
      });
    }
    
    next();
  };
};

// 5. Session fixation protection
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.session && !req.session.regenerated) {
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.regenerated = true;
      next();
    });
  } else {
    next();
  }
});
```

### 🏗️ Scenario 2: Microservices Authentication Architecture
**Situation:** You're designing authentication for a microservices architecture with 50+ services. Each service needs to verify requests while maintaining performance and security.

**Requirements:**
1. Centralized authentication service
2. Service-to-service authentication
3. User context propagation
4. Performance under high load
5. Audit trail across services

**Architecture Design:**
```typescript
// 1. Centralized Auth Service
class AuthService {
  async authenticateUser(credentials: Credentials): Promise<AuthResult> {
    // Validate credentials
    // Generate tokens
    // Store session
    return result;
  }
  
  async verifyToken(token: string): Promise<TokenInfo> {
    // Fast token validation with caching
    const cached = await redis.get(`token:${token}`);
    if (cached) return JSON.parse(cached);
    
    // Validate and cache
    const info = await this.validateToken(token);
    await redis.setex(`token:${token}`, 300, JSON.stringify(info));
    return info;
  }
}

// 2. Service-to-service authentication with mTLS
class ServiceAuth {
  private certificate: string;
  private privateKey: string;
  
  async authenticateService(request: ServiceRequest): Promise<boolean> {
    // Verify client certificate
    // Check service permissions
    return isValid;
  }
}

// 3. User context propagation with JWT
const propagateUserContext = (req: Request, res: Response, next: NextFunction) => {
  const userContext = {
    userId: req.user?.sub,
    roles: req.user?.roles,
    permissions: req.user?.permissions,
    requestId: req.id,
    sessionId: req.session?.id
  };
  
  // Add to headers for downstream services
  req.headers['x-user-context'] = Buffer.from(
    JSON.stringify(userContext)
  ).toString('base64');
  
  next();
};

// 4. Performance optimization with edge authentication
// Use API Gateway for authentication
const apiGatewayConfig = {
  authentication: {
    type: 'jwt',
    jwksUri: 'https://auth.example.com/.well-known/jwks.json',
    issuer: 'https://auth.example.com',
    audience: ['service1', 'service2', 'service3']
  },
  rateLimiting: {
    enabled: true,
    perUser: 1000,
    perIp: 10000
  }
};

// 5. Distributed audit logging
class AuditLogger {
  async log(event: AuditEvent): Promise<void> {
    // Send to centralized logging system
    await kafka.produce('audit-logs', {
      ...event,
      service: process.env.SERVICE_NAME,
      timestamp: new Date().toISOString(),
      traceId: req.traceId
    });
  }
}
```

### 🔄 Scenario 3: Migration from Legacy Session System to JWT
**Situation:** A legacy application uses server-side sessions with sticky sessions on load balancer. Need to migrate to stateless JWT authentication while maintaining zero downtime.

**Challenges:**
1. Existing active sessions must remain valid
2. Load balancer configuration changes
3. Client-side code updates
4. Database session cleanup
5. Monitoring during migration

**Migration Strategy:**
```typescript
// Phase 1: Dual support
app.use(async (req: Request, res: Response, next: NextFunction) => {
  // Try JWT first
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const user = await jwtService.verifyToken(token);
      req.user = user;
      return next();
    } catch {
      // JWT invalid, fall back to session
    }
  }
  
  // Fall back to session
  if (req.session?.userId) {
    const user = await userService.findById(req.session.userId);
    if (user) {
      req.user = user;
      
      // Issue JWT for future requests
      const newToken = await jwtService.createToken(user);
      res.setHeader('X-New-Token', newToken);
    }
  }
  
  next();
});

// Phase 2: Client migration
// Update clients to use JWT, with fallback to sessions
class ApiClient {
  async request(endpoint: string, data?: any) {
    let token = localStorage.getItem('jwt_token');
    
    if (!token) {
      // Fall back to session cookie
      return this.makeRequestWithCookies(endpoint, data);
    }
    
    try {
      return await this.makeRequestWithJWT(endpoint, data, token);
    } catch (error) {
      if (error.status === 401) {
        // Token expired, try to refresh
        token = await this.refreshToken();
        if (token) {
          return await this.makeRequestWithJWT(endpoint, data, token);
        }
      }
      throw error;
    }
  }
}

// Phase 3: Session cleanup
// Run background job to migrate sessions
class SessionMigrationJob {
  async migrateSessions() {
    const sessions = await sessionRepository.findActiveSessions();
    
    for (const session of sessions) {
      const user = await userService.findById(session.userId);
      if (user) {
        const jwt = await jwtService.createToken(user);
        await jwtRepository.save({
          userId: user.id,
          token: jwt,
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        });
      }
    }
  }
}

// Phase 4: Monitoring
const migrationMetrics = {
  sessionsMigrated: 0,
  jwtIssued: 0,
  fallbackRequests: 0,
  errors: 0
};

// Export metrics to monitoring system
setInterval(() => {
  metricsClient.record('auth.migration', migrationMetrics);
}, 60000);
```

### 🛡️ Scenario 4: Implementing Zero-Trust Authentication
**Situation:** A healthcare application needs to implement zero-trust authentication for HIPAA compliance. Every request must be verified, regardless of origin.

**Zero-Trust Principles:**
1. Never trust, always verify
2. Least privilege access
3. Assume breach
4. Continuous verification

**Implementation:**
```typescript
// 1. Continuous verification middleware
const zeroTrustMiddleware = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Verify request on multiple factors
    const verificationResults = await Promise.all([
      this.verifyToken(req),
      this.verifyDevice(req),
      this.verifyLocation(req),
      this.verifyBehavior(req)
    ]);
    
    const riskScore = this.calculateRiskScore(verificationResults);
    
    if (riskScore > 0.7) {
      // High risk - require step-up authentication
      return this.requireStepUpAuth(req, res);
    }
    
    if (riskScore > 0.3) {
      // Medium risk - add additional logging
      await this.logSuspiciousActivity(req, riskScore);
    }
    
    next();
  };
};

// 2. Device verification
class DeviceVerificationService {
  async verifyDevice(req: Request): Promise<DeviceVerification> {
    const deviceFingerprint = this.generateFingerprint(req);
    const knownDevices = await this.getUserDevices(req.user.sub);
    
    const isKnownDevice = knownDevices.some(device => 
      device.fingerprint === deviceFingerprint
    );
    
    const isCompromised = await this.checkDeviceCompromise(deviceFingerprint);
    
    return {
      isKnownDevice,
      isCompromised,
      fingerprint: deviceFingerprint
    };
  }
}

// 3. Location verification
class LocationVerificationService {
  async verifyLocation(req: Request): Promise<LocationVerification> {
    const ip = req.ip;
    const previousLocations = await this.getUserLocations(req.user.sub);
    
    const currentLocation = await this.geolocateIp(ip);
    const isSuspicious = this.isLocationSuspicious(
      currentLocation,
      previousLocations
    );
    
    return {
      location: currentLocation,
      isSuspicious,
      velocity: this.calculateVelocity(previousLocations, currentLocation)
    };
  }
}

// 4. Behavioral analysis
class BehavioralAnalysisService {
  async analyzeBehavior(req: Request): Promise<BehaviorAnalysis> {
    const userPattern = await this.getUserPattern(req.user.sub);
    const currentBehavior = this.extractBehavior(req);
    
    const anomalies = this.detectAnomalies(userPattern, currentBehavior);
    
    return {
      anomalyScore: anomalies.length > 0 ? 0.8 : 0.1,
      anomalies,
      confidence: this.calculateConfidence(userPattern)
    };
  }
}

// 5. Risk-based access control
class RiskBasedAccessControl {
  async checkAccess(
    req: Request,
    resource: string,
    action: string
  ): Promise<AccessDecision> {
    const riskScore = await this.calculateRequestRisk(req);
    const sensitivity = this.getResourceSensitivity(resource);
    
    const allowed = riskScore <= (1 - sensitivity);
    
    return {
      allowed,
      riskScore,
      sensitivity,
      requiredVerification: !allowed ? 'step_up' : 'none'
    };
  }
}
```

### 🔐 Scenario 5: Implementing Passwordless Authentication
**Situation:** A modern SaaS application wants to implement passwordless authentication using WebAuthn and magic links to improve UX and security.

**Requirements:**
1. Support WebAuthn (biometrics, security keys)
2. Magic links via email
3. SMS OTP as fallback
4. Recovery mechanisms
5. Progressive enhancement

**Implementation:**
```typescript
// 1. WebAuthn registration
class WebAuthnService {
  async registerStart(userId: string): Promise<PublicKeyCredentialCreationOptions> {
    const user = await this.userRepository.findById(userId);
    
    return {
      challenge: randomBytes(32),
      rp: {
        name: 'MyApp',
        id: process.env.RP_ID
      },
      user: {
        id: Buffer.from(userId),
        name: user.email,
        displayName: user.name
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 } // RS256
      ],
      timeout: 60000,
      attestation: 'direct',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        requireResidentKey: true,
        userVerification: 'required'
      }
    };
  }
  
  async registerFinish(
    userId: string,
    credential: any
  ): Promise<void> {
    // Verify credential
    const verification = await this.verifyRegistration(credential);
    
    // Store credential
    await this.credentialRepository.save({
      userId,
      credentialId: verification.credentialId,
      publicKey: verification.publicKey,
      counter: verification.counter,
      transports: credential.transports,
      registeredAt: new Date()
    });
  }
}

// 2. Magic link authentication
class MagicLinkService {
  async sendMagicLink(email: string): Promise<void> {
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    
    await this.magicLinkRepository.save({
      email,
      token,
      expiresAt,
      used: false
    });
    
    const magicLink = `${process.env.APP_URL}/auth/magic/${token}`;
    
    await this.emailService.send({
      to: email,
      subject: 'Your Magic Link',
      html: this.generateMagicLinkEmail(magicLink)
    });
  }
  
  async verifyMagicLink(token: string): Promise<AuthResult> {
    const magicLink = await this.magicLinkRepository.findByToken(token);
    
    if (!magicLink || magicLink.used || magicLink.expiresAt < new Date()) {
      throw new InvalidMagicLinkError();
    }
    
    // Mark as used
    await this.magicLinkRepository.markAsUsed(magicLink.id);
    
    // Get or create user
    let user = await this.userRepository.findByEmail(magicLink.email);
    
    if (!user) {
      user = await this.userRepository.create({
        email: magicLink.email,
        authMethod: 'magic_link'
      });
    }
    
    // Generate session
    return this.authService.createSession(user);
  }
}

// 3. Progressive authentication flow
class AuthenticationOrchestrator {
  async authenticate(
    request: AuthRequest,
    context: AuthContext
  ): Promise<AuthResult> {
    // Step 1: Check for passwordless options
    const user = await this.userRepository.findByEmail(request.email);
    
    if (user) {
      // Check preferred authentication method
      const preferredMethod = await this.getPreferredMethod(user.id);
      
      switch (preferredMethod) {
        case 'webauthn':
          return this.authenticateWithWebAuthn(user, context);
        case 'magic_link':
          return this.authenticateWithMagicLink(user, context);
        case 'sms':
          return this.authenticateWithSMS(user, context);
        default:
          // Fall back to traditional methods
          return this.authenticateWithPassword(user, request.password!);
      }
    } else {
      // New user - start with magic link
      return this.authenticateWithMagicLink(
        { email: request.email } as User,
        context
      );
    }
  }
}

// 4. Recovery mechanisms
class AccountRecoveryService {
  async recoverAccount(email: string): Promise<RecoveryOptions> {
    const user = await this.userRepository.findByEmail(email);
    
    if (!user) {
      // Don't reveal if user exists
      return { options: ['email'] };
    }
    
    const options: RecoveryOption[] = [];
    
    // Check available recovery methods
    if (user.phone && user.phoneVerified) {
      options.push('sms');
    }
    
    if (await this.hasBackupEmail(user.id)) {
      options.push('backup_email');
    }
    
    if (await this.hasSecurityQuestions(user.id)) {
      options.push('security_questions');
    }
    
    // Always allow email as last resort
    options.push('email');
    
    return { options };
  }
  
  async recoverWithMethod(
    email: string,
    method: RecoveryMethod,
    data?: any
  ): Promise<RecoveryResult> {
    // Implement recovery flow based on method
    switch (method) {
      case 'sms':
        return this.recoverWithSMS(email, data);
      case 'email':
        return this.recoverWithEmail(email);
      case 'backup_email':
        return this.recoverWithBackupEmail(email);
      case 'security_questions':
        return this.recoverWithSecurityQuestions(email, data);
      default:
        throw new InvalidRecoveryMethodError();
    }
  }
}

// 5. UX-optimized authentication flow
const authFlowMiddleware = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Detect client capabilities
    const capabilities = this.detectCapabilities(req);
    
    // Choose optimal authentication flow
    let flow: AuthFlow;
    
    if (capabilities.webauthn) {
      flow = 'webauthn';
    } else if (capabilities.cookies && capabilities.https) {
      flow = 'magic_link';
    } else {
      flow = 'traditional';
    }
    
    // Add flow information to response
    res.locals.authFlow = flow;
    res.setHeader('X-Auth-Flow', flow);
    
    next();
  };
};
```

---

## 📚 Additional Resources

### Documentation
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [RFC 6749 - OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 7519 - JWT](https://tools.ietf.org/html/rfc7519)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)

### Security Tools
- [Helmet.js](https://helmetjs.github.io/) - Security headers
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- [argon2](https://github.com/ranisalt/node-argon2) - Password hashing
- [speakeasy](https://github.com/speakeasyjs/speakeasy) - 2FA/TOTP
- [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn) - WebAuthn

### Monitoring & Auditing
- [Pino](https://getpino.io/) - Structured logging
- [Winston](https://github.com/winstonjs/winston)
- [OpenTelemetry](https://opentelemetry.io/) - Distributed tracing
- [ELK Stack](https://www.elastic.co/what-is/elk-stack) - Log analysis

### Testing
- [Jest](https://jestjs.io/)
- [Supertest](https://github.com/visionmedia/supertest)
- [OWASP ZAP](https://www.zaproxy.org/) - Security testing
- [Burp Suite](https://portswigger.net/burp) - Web security testing

### Best Practices
1. Always use HTTPS in production
2. Implement proper rate limiting
3. Use secure, HTTP-only cookies
4. Regularly rotate secrets and keys
5. Implement proper error handling (don't leak information)
6. Use CSRF protection for state-changing operations
7. Implement proper session management
8. Regularly audit and update dependencies
9. Use security headers (CSP, HSTS, etc.)
10. Implement proper logging and monitoring

---
