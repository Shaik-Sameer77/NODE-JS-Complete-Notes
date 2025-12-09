# Hands-on Backend Implementations: Comprehensive Guide

## 📚 Table of Contents
1. [Authentication System](#1-authentication-system)
2. [Role-based Permissions](#2-role-based-permissions)
3. [CRUD with PostgreSQL & MongoDB](#3-crud-with-postgresql--mongodb)
4. [File Uploads](#4-file-uploads)
5. [Real-time Chat](#5-real-time-chat)
6. [Online/Offline Status Tracker](#6-onlineoffline-status-tracker)
7. [Payment Gateway](#7-payment-gateway)
8. [Email Service](#8-email-service)
9. [Refresh Token Rotation](#9-refresh-token-rotation)
10. [Background Jobs](#10-background-jobs)
11. [Cloud Storage System](#11-cloud-storage-system)
12. [Multi-tenant Architecture](#12-multi-tenant-architecture)

---

## 1. Authentication System

### 📖 In-Depth Explanation

A comprehensive authentication system handles user registration, login, password management, and session handling securely.

#### **Complete Authentication System with TypeScript**

```typescript
// src/auth/auth.service.ts
import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { RedisService } from '../redis/redis.service';
import { EmailService } from '../email/email.service';
import { UserService } from '../user/user.service';
import { SessionService } from '../session/session.service';
import {
  LoginDto,
  RegisterDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  ChangePasswordDto,
  VerifyEmailDto,
} from './dto';

interface TokenPayload {
  sub: string;
  email: string;
  sessionId: string;
  type: 'access' | 'refresh';
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly emailService: EmailService,
    private readonly sessionService: SessionService,
  ) {}

  private readonly SALT_ROUNDS = 12;
  private readonly ACCESS_TOKEN_EXPIRY = '15m';
  private readonly REFRESH_TOKEN_EXPIRY = '7d';
  private readonly PASSWORD_RESET_EXPIRY = 3600; // 1 hour
  private readonly EMAIL_VERIFICATION_EXPIRY = 86400; // 24 hours

  async register(registerDto: RegisterDto) {
    const { email, password, name } = registerDto;

    // Check if user exists
    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Validate password strength
    this.validatePasswordStrength(password);

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Generate email verification token
    const verificationToken = this.generateToken();
    const verificationTokenHash = await this.hashToken(verificationToken);

    // Create user
    const user = await this.userService.create({
      email,
      password: hashedPassword,
      name,
      emailVerificationToken: verificationTokenHash,
      emailVerified: false,
      status: 'pending',
    });

    // Send verification email
    await this.emailService.sendVerificationEmail(
      email,
      name,
      verificationToken,
    );

    // Generate initial session
    const session = await this.sessionService.create({
      userId: user.id,
      userAgent: registerDto.userAgent,
      ipAddress: registerDto.ipAddress,
    });

    // Generate tokens
    const tokens = await this.generateTokens(user, session.id);

    // Remove sensitive data
    const { password: _, emailVerificationToken: __, ...userWithoutSensitive } = user;

    return {
      user: userWithoutSensitive,
      tokens,
      session,
    };
  }

  async login(loginDto: LoginDto) {
    const { email, password, userAgent, ipAddress } = loginDto;

    // Find user
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if account is locked
    if (user.failedLoginAttempts >= 5) {
      const lockTime = new Date(user.lockedUntil);
      if (lockTime > new Date()) {
        throw new ForbiddenException('Account is temporarily locked');
      }
    }

    // Verify password
    const isPasswordValid = await this.verifyPassword(
      password,
      user.password,
    );

    if (!isPasswordValid) {
      // Increment failed login attempts
      await this.userService.incrementFailedLoginAttempts(user.id);

      if (user.failedLoginAttempts + 1 >= 5) {
        await this.userService.lockAccount(user.id, 30); // Lock for 30 minutes
        throw new ForbiddenException('Account has been locked due to too many failed attempts');
      }

      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset failed login attempts on successful login
    await this.userService.resetFailedLoginAttempts(user.id);

    // Check if email is verified
    if (!user.emailVerified) {
      throw new ForbiddenException('Please verify your email address');
    }

    // Create new session
    const session = await this.sessionService.create({
      userId: user.id,
      userAgent,
      ipAddress,
    });

    // Generate tokens
    const tokens = await this.generateTokens(user, session.id);

    // Update last login
    await this.userService.updateLastLogin(user.id);

    // Remove sensitive data
    const { password: _, ...userWithoutPassword } = user;

    return {
      user: userWithoutPassword,
      tokens,
      session,
    };
  }

  async logout(sessionId: string) {
    // Blacklist tokens and remove session
    await Promise.all([
      this.sessionService.revoke(sessionId),
      this.redisService.setex(`blacklist:${sessionId}`, 3600, 'true'), // Blacklist for 1 hour
    ]);
  }

  async logoutAll(userId: string) {
    await this.sessionService.revokeAll(userId);
  }

  async refreshTokens(refreshToken: string) {
    try {
      // Verify refresh token
      const payload = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        {
          secret: process.env.JWT_REFRESH_SECRET,
        },
      );

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.redisService.get(
        `blacklist:${payload.sessionId}`,
      );
      if (isBlacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }

      // Get user and session
      const [user, session] = await Promise.all([
        this.userService.findById(payload.sub),
        this.sessionService.findById(payload.sessionId),
      ]);

      if (!user || !session || session.revoked) {
        throw new UnauthorizedException('Invalid session');
      }

      // Generate new tokens
      const tokens = await this.generateTokens(user, session.id);

      // Update session last activity
      await this.sessionService.updateLastActivity(session.id);

      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;

    const user = await this.userService.findByEmail(email);
    if (!user) {
      // Return success even if user doesn't exist (security best practice)
      return { message: 'If an account exists, a reset link has been sent' };
    }

    // Generate reset token
    const resetToken = this.generateToken();
    const resetTokenHash = await this.hashToken(resetToken);

    // Store token hash with expiry
    await this.redisService.setex(
      `password_reset:${resetTokenHash}`,
      this.PASSWORD_RESET_EXPIRY,
      user.id,
    );

    // Send reset email
    await this.emailService.sendPasswordResetEmail(
      user.email,
      user.name,
      resetToken,
    );

    return { message: 'If an account exists, a reset link has been sent' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, newPassword } = resetPasswordDto;

    // Hash token to compare with stored hash
    const tokenHash = await this.hashToken(token);

    // Get user ID from Redis
    const userId = await this.redisService.get(`password_reset:${tokenHash}`);
    if (!userId) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Validate password strength
    this.validatePasswordStrength(newPassword);

    // Hash new password
    const hashedPassword = await this.hashPassword(newPassword);

    // Update password
    await this.userService.updatePassword(userId, hashedPassword);

    // Delete used token
    await this.redisService.del(`password_reset:${tokenHash}`);

    // Revoke all sessions (security measure)
    await this.sessionService.revokeAll(userId);

    return { message: 'Password has been reset successfully' };
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ) {
    const { currentPassword, newPassword } = changePasswordDto;

    // Get user with password
    const user = await this.userService.findByIdWithPassword(userId);

    // Verify current password
    const isValid = await this.verifyPassword(
      currentPassword,
      user.password,
    );

    if (!isValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Validate new password strength
    this.validatePasswordStrength(newPassword);

    // Hash new password
    const hashedPassword = await this.hashPassword(newPassword);

    // Update password
    await this.userService.updatePassword(userId, hashedPassword);

    // Revoke all sessions except current (optional)
    // await this.sessionService.revokeAllExcept(userId, currentSessionId);

    return { message: 'Password changed successfully' };
  }

  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const { token } = verifyEmailDto;

    // Hash token
    const tokenHash = await this.hashToken(token);

    // Find user with this verification token
    const user = await this.userService.findByVerificationToken(tokenHash);
    if (!user) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    // Verify email
    await this.userService.verifyEmail(user.id);

    // Delete verification token
    await this.userService.clearVerificationToken(user.id);

    return { message: 'Email verified successfully' };
  }

  async resendVerificationEmail(email: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      // Don't reveal if user exists
      return { message: 'If an account exists, a verification email has been sent' };
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    // Generate new verification token
    const verificationToken = this.generateToken();
    const verificationTokenHash = await this.hashToken(verificationToken);

    // Update user with new token
    await this.userService.updateVerificationToken(
      user.id,
      verificationTokenHash,
    );

    // Send verification email
    await this.emailService.sendVerificationEmail(
      user.email,
      user.name,
      verificationToken,
    );

    return { message: 'Verification email sent' };
  }

  private async generateTokens(user: any, sessionId: string) {
    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
      sessionId,
      type: 'access',
    };

    const refreshPayload: TokenPayload = {
      ...payload,
      type: 'refresh',
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: this.ACCESS_TOKEN_EXPIRY,
      }),
      this.jwtService.signAsync(refreshPayload, {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: this.REFRESH_TOKEN_EXPIRY,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: 900, // 15 minutes in seconds
    };
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  private async verifyPassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  private async hashToken(token: string): Promise<string> {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private validatePasswordStrength(password: string): void {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException(
        `Password must be at least ${minLength} characters long`,
      );
    }

    if (!hasUpperCase || !hasLowerCase) {
      throw new BadRequestException(
        'Password must contain both uppercase and lowercase letters',
      );
    }

    if (!hasNumbers) {
      throw new BadRequestException('Password must contain at least one number');
    }

    if (!hasSpecialChars) {
      throw new BadRequestException(
        'Password must contain at least one special character',
      );
    }

    // Check for common passwords
    const commonPasswords = [
      'password',
      '123456',
      'qwerty',
      'letmein',
      'welcome',
    ];
    if (commonPasswords.includes(password.toLowerCase())) {
      throw new BadRequestException('Password is too common');
    }
  }

  // Security monitoring
  async logSecurityEvent(
    userId: string,
    eventType: string,
    details: Record<string, any>,
  ) {
    await this.redisService.publish('security-events', JSON.stringify({
      userId,
      eventType,
      details,
      timestamp: new Date().toISOString(),
      ipAddress: details.ipAddress,
      userAgent: details.userAgent,
    }));
  }
}
```

#### **JWT Strategy with Redis Blacklist**

```typescript
// src/auth/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { RedisService } from '../redis/redis.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly redisService: RedisService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          let token = null;
          if (req && req.cookies) {
            token = req.cookies['access_token'];
          }
          return token || ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        },
      ]),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
      ignoreExpiration: false,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    // Check if token is blacklisted
    const isBlacklisted = await this.redisService.get(
      `blacklist:${payload.sessionId}`,
    );
    
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // Get additional user data if needed
    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.sessionId,
      // Add any other claims you need
    };
  }
}

// Refresh token strategy
@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly redisService: RedisService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req) => {
          let token = null;
          if (req && req.cookies) {
            token = req.cookies['refresh_token'];
          }
          return token;
        },
      ]),
      secretOrKey: process.env.JWT_REFRESH_SECRET,
      ignoreExpiration: false,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid token type');
    }

    // Check if refresh token is blacklisted
    const isBlacklisted = await this.redisService.get(
      `blacklist:${payload.sessionId}`,
    );
    
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      sessionId: payload.sessionId,
    };
  }
}
```

#### **Session Management**

```typescript
// src/session/session.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { RedisService } from '../redis/redis.service';

interface SessionDocument {
  id: string;
  userId: string;
  userAgent: string;
  ipAddress: string;
  lastActivity: Date;
  createdAt: Date;
  revoked: boolean;
}

@Injectable()
export class SessionService {
  constructor(
    @InjectModel('Session') private sessionModel: Model<SessionDocument>,
    private readonly redisService: RedisService,
  ) {}

  async create(sessionData: {
    userId: string;
    userAgent: string;
    ipAddress: string;
  }) {
    const session = new this.sessionModel({
      ...sessionData,
      id: this.generateSessionId(),
      lastActivity: new Date(),
      createdAt: new Date(),
      revoked: false,
    });

    await session.save();

    // Cache session in Redis
    await this.redisService.setex(
      `session:${session.id}`,
      86400, // 24 hours
      JSON.stringify({
        userId: session.userId,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
      }),
    );

    return session;
  }

  async findById(sessionId: string) {
    // Try cache first
    const cached = await this.redisService.get(`session:${sessionId}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Fall back to database
    const session = await this.sessionModel.findOne({
      id: sessionId,
      revoked: false,
    });

    if (session) {
      // Update cache
      await this.redisService.setex(
        `session:${sessionId}`,
        3600,
        JSON.stringify(session),
      );
    }

    return session;
  }

  async revoke(sessionId: string) {
    await Promise.all([
      this.sessionModel.updateOne(
        { id: sessionId },
        { revoked: true, revokedAt: new Date() },
      ),
      this.redisService.del(`session:${sessionId}`),
      this.redisService.setex(`blacklist:${sessionId}`, 3600, 'true'),
    ]);
  }

  async revokeAll(userId: string) {
    const sessions = await this.sessionModel.find({
      userId,
      revoked: false,
    });

    await Promise.all([
      this.sessionModel.updateMany(
        { userId, revoked: false },
        { revoked: true, revokedAt: new Date() },
      ),
      ...sessions.map((session) =>
        Promise.all([
          this.redisService.del(`session:${session.id}`),
          this.redisService.setex(`blacklist:${session.id}`, 3600, 'true'),
        ]),
      ),
    ]);
  }

  async updateLastActivity(sessionId: string) {
    await this.sessionModel.updateOne(
      { id: sessionId },
      { lastActivity: new Date() },
    );
  }

  async getUserSessions(userId: string) {
    return this.sessionModel.find({
      userId,
      revoked: false,
    }).sort({ lastActivity: -1 });
  }

  async cleanupExpiredSessions(maxAgeDays: number = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - maxAgeDays);

    const expiredSessions = await this.sessionModel.find({
      lastActivity: { $lt: cutoffDate },
      revoked: false,
    });

    await Promise.all([
      this.sessionModel.updateMany(
        { lastActivity: { $lt: cutoffDate }, revoked: false },
        { revoked: true, revokedAt: new Date() },
      ),
      ...expiredSessions.map((session) =>
        this.redisService.del(`session:${session.id}`),
      ),
    ]);

    return expiredSessions.length;
  }

  private generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
```

### 🎯 Real-World Scenario: Banking Application Authentication
*You're building authentication for a banking application that requires MFA, device management, and compliance with financial regulations. The system must prevent account takeover and support suspicious activity detection.*

**Interview Questions:**
1. How would you implement multi-factor authentication (MFA)?
2. What strategies would you use for device fingerprinting and recognition?
3. How do you detect and prevent brute force attacks?
4. What compliance requirements (PCI DSS, GDPR) affect authentication design?
5. How would you implement step-up authentication for sensitive operations?

**Technical Questions:**
1. How do you prevent JWT token theft and replay attacks?
2. What's the difference between session-based and token-based authentication?
3. How do you implement rate limiting for authentication endpoints?
4. What are the security considerations for password reset flows?

---

## 2. Role-based Permissions

### 📖 In-Depth Explanation

RBAC (Role-Based Access Control) with fine-grained permissions using a hierarchical permission system.

#### **Complete RBAC Implementation**

```typescript
// src/rbac/rbac.module.ts
import { Module, Global } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RbacService } from './rbac.service';
import { PermissionGuard } from './guards/permission.guard';
import { RoleGuard } from './guards/role.guard';
import {
  Role,
  Permission,
  UserRole,
  RolePermission,
  Resource,
} from './entities';

@Global()
@Module({
  imports: [
    TypeOrmModule.forFeature([
      Role,
      Permission,
      UserRole,
      RolePermission,
      Resource,
    ]),
  ],
  providers: [RbacService, PermissionGuard, RoleGuard],
  exports: [RbacService, PermissionGuard, RoleGuard],
})
export class RbacModule {}

// src/rbac/entities/index.ts
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToMany,
  JoinTable,
  OneToMany,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';

// Resource entity
@Entity('resources')
export class Resource {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @Column()
  description: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => Permission, (permission) => permission.resource)
  permissions: Permission[];
}

// Permission entity
@Entity('permissions')
@Index(['resourceId', 'action'], { unique: true })
export class Permission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column()
  action: string; // create, read, update, delete, approve, etc.

  @Column()
  resourceId: string;

  @ManyToOne(() => Resource, (resource) => resource.permissions)
  @JoinColumn({ name: 'resourceId' })
  resource: Resource;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}

// Role entity with hierarchy support
@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @Column()
  description: string;

  @Column({ nullable: true })
  parentId: string;

  @ManyToOne(() => Role, (role) => role.children)
  @JoinColumn({ name: 'parentId' })
  parent: Role;

  @OneToMany(() => Role, (role) => role.parent)
  children: Role[];

  @Column({ type: 'int', default: 0 })
  level: number; // Hierarchy level for quick lookup

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToMany(() => Permission, (permission) => permission.roles)
  @JoinTable({
    name: 'role_permissions',
    joinColumn: { name: 'roleId', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'permissionId', referencedColumnName: 'id' },
  })
  permissions: Permission[];

  @OneToMany(() => UserRole, (userRole) => userRole.role)
  userRoles: UserRole[];
}

// User-Role mapping
@Entity('user_roles')
@Index(['userId', 'roleId'], { unique: true })
export class UserRole {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  roleId: string;

  @ManyToOne(() => Role, (role) => role.userRoles)
  @JoinColumn({ name: 'roleId' })
  role: Role;

  @Column({ type: 'jsonb', nullable: true })
  context: Record<string, any>; // Context-specific role data

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}

// Role-Permission mapping (explicit table for additional metadata)
@Entity('role_permissions')
@Index(['roleId', 'permissionId'], { unique: true })
export class RolePermission {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  roleId: string;

  @Column()
  permissionId: string;

  @ManyToOne(() => Role)
  @JoinColumn({ name: 'roleId' })
  role: Role;

  @ManyToOne(() => Permission)
  @JoinColumn({ name: 'permissionId' })
  permission: Permission;

  @Column({ type: 'jsonb', nullable: true })
  conditions: Record<string, any>; // Conditional permissions

  @Column({ type: 'jsonb', nullable: true })
  fields: string[]; // Field-level permissions

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

#### **RBAC Service with Caching**

```typescript
// src/rbac/rbac.service.ts
import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, In, TreeRepository } from 'typeorm';
import { RedisService } from '../redis/redis.service';
import {
  Role,
  Permission,
  UserRole,
  RolePermission,
  Resource,
} from './entities';

interface PermissionCheckOptions {
  userId: string;
  resource: string;
  action: string;
  context?: Record<string, any>;
}

interface RoleAssignment {
  userId: string;
  roleId: string;
  context?: Record<string, any>;
}

@Injectable()
export class RbacService {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
    @InjectRepository(UserRole)
    private readonly userRoleRepository: Repository<UserRole>,
    @InjectRepository(RolePermission)
    private readonly rolePermissionRepository: Repository<RolePermission>,
    @InjectRepository(Resource)
    private readonly resourceRepository: Repository<Resource>,
    @InjectRepository(Role)
    private readonly roleTreeRepository: TreeRepository<Role>,
    private readonly redisService: RedisService,
  ) {}

  private readonly CACHE_TTL = 3600; // 1 hour
  private readonly USER_PERMISSIONS_CACHE_KEY = 'user_permissions';

  // Resource Management
  async createResource(data: {
    name: string;
    description: string;
  }) {
    const existingResource = await this.resourceRepository.findOne({
      where: { name: data.name },
    });

    if (existingResource) {
      throw new ConflictException('Resource already exists');
    }

    const resource = this.resourceRepository.create(data);
    return this.resourceRepository.save(resource);
  }

  async createPermission(data: {
    name: string;
    action: string;
    resourceId: string;
    description?: string;
  }) {
    const resource = await this.resourceRepository.findOne({
      where: { id: data.resourceId },
    });

    if (!resource) {
      throw new NotFoundException('Resource not found');
    }

    const existingPermission = await this.permissionRepository.findOne({
      where: {
        resourceId: data.resourceId,
        action: data.action,
      },
    });

    if (existingPermission) {
      throw new ConflictException('Permission already exists for this resource');
    }

    const permission = this.permissionRepository.create({
      ...data,
      resource,
    });

    return this.permissionRepository.save(permission);
  }

  // Role Management with Hierarchy
  async createRole(data: {
    name: string;
    description: string;
    parentId?: string;
    permissionIds?: string[];
  }) {
    const existingRole = await this.roleRepository.findOne({
      where: { name: data.name },
    });

    if (existingRole) {
      throw new ConflictException('Role already exists');
    }

    let parent = null;
    if (data.parentId) {
      parent = await this.roleRepository.findOne({
        where: { id: data.parentId },
      });
      if (!parent) {
        throw new NotFoundException('Parent role not found');
      }
    }

    const role = this.roleRepository.create({
      name: data.name,
      description: data.description,
      parent,
      level: parent ? parent.level + 1 : 0,
    });

    const savedRole = await this.roleRepository.save(role);

    // Assign permissions if provided
    if (data.permissionIds && data.permissionIds.length > 0) {
      await this.assignPermissionsToRole(savedRole.id, data.permissionIds);
    }

    // Invalidate cache
    await this.invalidateRoleCache(savedRole.id);

    return savedRole;
  }

  async getRoleWithHierarchy(roleId: string): Promise<Role> {
    const role = await this.roleTreeRepository.findOne({
      where: { id: roleId },
      relations: ['parent', 'children'],
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return role;
  }

  async getRolePermissions(roleId: string, includeInherited = true): Promise<Permission[]> {
    const cacheKey = `role_permissions:${roleId}:${includeInherited}`;
    
    // Try cache first
    const cached = await this.redisService.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    const role = await this.getRoleWithHierarchy(roleId);
    const roleIds = [role.id];

    // Get all parent roles if including inherited
    if (includeInherited) {
      let current = role;
      while (current.parent) {
        roleIds.push(current.parent.id);
        current = current.parent;
      }
    }

    // Get permissions for all roles
    const permissions = await this.permissionRepository
      .createQueryBuilder('permission')
      .innerJoin('permission.roles', 'role')
      .where('role.id IN (:...roleIds)', { roleIds })
      .distinct(true)
      .getMany();

    // Cache result
    await this.redisService.setex(
      cacheKey,
      this.CACHE_TTL,
      JSON.stringify(permissions),
    );

    return permissions;
  }

  // Permission Assignment
  async assignPermissionsToRole(roleId: string, permissionIds: string[]) {
    const role = await this.roleRepository.findOne({
      where: { id: roleId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    const permissions = await this.permissionRepository.find({
      where: { id: In(permissionIds) },
    });

    if (permissions.length !== permissionIds.length) {
      throw new NotFoundException('Some permissions not found');
    }

    // Remove existing assignments
    await this.rolePermissionRepository.delete({ roleId });

    // Create new assignments
    const rolePermissions = permissions.map((permission) =>
      this.rolePermissionRepository.create({
        roleId,
        permissionId: permission.id,
      }),
    );

    await this.rolePermissionRepository.save(rolePermissions);

    // Invalidate cache
    await this.invalidateRoleCache(roleId);
    await this.invalidateUserPermissionsCacheForRole(roleId);
  }

  // User Role Assignment
  async assignRoleToUser(assignment: RoleAssignment) {
    const { userId, roleId, context } = assignment;

    const role = await this.roleRepository.findOne({
      where: { id: roleId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    const existingAssignment = await this.userRoleRepository.findOne({
      where: { userId, roleId },
    });

    if (existingAssignment) {
      throw new ConflictException('User already has this role');
    }

    const userRole = this.userRoleRepository.create({
      userId,
      roleId,
      context,
    });

    await this.userRoleRepository.save(userRole);

    // Invalidate user permissions cache
    await this.invalidateUserPermissionsCache(userId);

    return userRole;
  }

  async getUserRoles(userId: string): Promise<Role[]> {
    const userRoles = await this.userRoleRepository.find({
      where: { userId, isActive: true },
      relations: ['role'],
    });

    return userRoles.map((ur) => ur.role);
  }

  // Permission Checking
  async checkPermission(options: PermissionCheckOptions): Promise<boolean> {
    const { userId, resource, action, context } = options;

    // Get user permissions with caching
    const userPermissions = await this.getUserPermissions(userId);

    // Find matching permission
    const permission = userPermissions.find(
      (p) => p.resource.name === resource && p.action === action,
    );

    if (!permission) {
      return false;
    }

    // Check context conditions if provided
    if (context) {
      const rolePermission = await this.rolePermissionRepository.findOne({
        where: {
          permissionId: permission.id,
          role: {
            userRoles: { userId },
          },
        },
        relations: ['role', 'role.userRoles'],
      });

      if (rolePermission?.conditions) {
        return this.evaluateConditions(rolePermission.conditions, context);
      }
    }

    return true;
  }

  async getUserPermissions(userId: string): Promise<Permission[]> {
    const cacheKey = `${this.USER_PERMISSIONS_CACHE_KEY}:${userId}`;

    // Try cache first
    const cached = await this.redisService.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get user roles
    const userRoles = await this.getUserRoles(userId);

    // Get permissions from all roles (including inherited)
    const allPermissions = new Map<string, Permission>();

    for (const role of userRoles) {
      const rolePermissions = await this.getRolePermissions(role.id, true);
      
      rolePermissions.forEach((permission) => {
        if (!allPermissions.has(permission.id)) {
          allPermissions.set(permission.id, permission);
        }
      });
    }

    const permissions = Array.from(allPermissions.values());

    // Cache result
    await this.redisService.setex(
      cacheKey,
      this.CACHE_TTL,
      JSON.stringify(permissions),
    );

    return permissions;
  }

  // Field-level permissions
  async getFieldPermissions(
    userId: string,
    resource: string,
  ): Promise<Record<string, string[]>> {
    const userRoles = await this.getUserRoles(userId);
    const fieldPermissions: Record<string, string[]> = {};

    for (const role of userRoles) {
      const rolePermissions = await this.rolePermissionRepository
        .createQueryBuilder('rp')
        .innerJoinAndSelect('rp.permission', 'permission')
        .innerJoinAndSelect('permission.resource', 'resource')
        .where('rp.roleId = :roleId', { roleId: role.id })
        .andWhere('resource.name = :resource', { resource })
        .andWhere('rp.fields IS NOT NULL')
        .getMany();

      rolePermissions.forEach((rp) => {
        if (rp.fields && rp.fields.length > 0) {
          const action = rp.permission.action;
          if (!fieldPermissions[action]) {
            fieldPermissions[action] = [];
          }
          fieldPermissions[action].push(...rp.fields);
        }
      });
    }

    // Remove duplicates
    Object.keys(fieldPermissions).forEach((action) => {
      fieldPermissions[action] = [...new Set(fieldPermissions[action])];
    });

    return fieldPermissions;
  }

  // Utility Methods
  private async evaluateConditions(
    conditions: Record<string, any>,
    context: Record<string, any>,
  ): Promise<boolean> {
    // Simple condition evaluation
    // In production, you might want to use a rules engine
    for (const [key, value] of Object.entries(conditions)) {
      if (context[key] !== value) {
        return false;
      }
    }
    return true;
  }

  private async invalidateRoleCache(roleId: string): Promise<void> {
    const pattern = `role_permissions:${roleId}:*`;
    const keys = await this.redisService.keys(pattern);
    if (keys.length > 0) {
      await this.redisService.del(...keys);
    }
  }

  private async invalidateUserPermissionsCache(userId: string): Promise<void> {
    const key = `${this.USER_PERMISSIONS_CACHE_KEY}:${userId}`;
    await this.redisService.del(key);
  }

  private async invalidateUserPermissionsCacheForRole(roleId: string): Promise<void> {
    // Get all users with this role
    const userRoles = await this.userRoleRepository.find({
      where: { roleId },
      select: ['userId'],
    });

    const userIds = userRoles.map((ur) => ur.userId);
    
    // Invalidate cache for each user
    await Promise.all(
      userIds.map((userId) => this.invalidateUserPermissionsCache(userId)),
    );
  }

  // Bulk permission checking
  async checkMultiplePermissions(
    userId: string,
    checks: Array<{ resource: string; action: string }>,
  ): Promise<Record<string, boolean>> {
    const userPermissions = await this.getUserPermissions(userId);
    const results: Record<string, boolean> = {};

    checks.forEach((check) => {
      const hasPermission = userPermissions.some(
        (p) => p.resource.name === check.resource && p.action === check.action,
      );
      results[`${check.resource}:${check.action}`] = hasPermission;
    });

    return results;
  }

  // Role-based data filtering
  async filterDataByRole<T>(
    userId: string,
    data: T[],
    resource: string,
    action: string,
  ): Promise<T[]> {
    const fieldPermissions = await this.getFieldPermissions(userId, resource);
    const allowedFields = fieldPermissions[action] || [];

    if (allowedFields.length === 0) {
      // No field restrictions, return all data
      return data;
    }

    // Filter data to include only allowed fields
    return data.map((item) => {
      const filteredItem = {} as T;
      allowedFields.forEach((field) => {
        if (field in item) {
          filteredItem[field] = item[field];
        }
      });
      return filteredItem;
    });
  }
}
```

#### **Permission Guards and Decorators**

```typescript
// src/rbac/guards/permission.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RbacService } from '../rbac.service';
import { Request } from 'express';

interface PermissionMetadata {
  resource: string;
  action: string;
  requireAll?: boolean;
}

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rbacService: RbacService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const userId = request.user?.userId;

    if (!userId) {
      throw new ForbiddenException('User not authenticated');
    }

    // Get permission metadata from handler or class
    const handlerPermission = this.reflector.get<PermissionMetadata>(
      'permission',
      context.getHandler(),
    );

    const classPermission = this.reflector.get<PermissionMetadata>(
      'permission',
      context.getClass(),
    );

    const permission = handlerPermission || classPermission;

    if (!permission) {
      // No permission required
      return true;
    }

    // Check permission
    const hasPermission = await this.rbacService.checkPermission({
      userId,
      resource: permission.resource,
      action: permission.action,
      context: this.buildContext(request),
    });

    if (!hasPermission) {
      throw new ForbiddenException(
        `Insufficient permissions: ${permission.resource}:${permission.action}`,
      );
    }

    return true;
  }

  private buildContext(request: Request): Record<string, any> {
    const context: Record<string, any> = {
      method: request.method,
      path: request.path,
      query: request.query,
      params: request.params,
      user: request.user,
    };

    // Add organization context if available
    if (request.headers['x-organization-id']) {
      context.organizationId = request.headers['x-organization-id'];
    }

    // Add tenant context if available
    if (request.headers['x-tenant-id']) {
      context.tenantId = request.headers['x-tenant-id'];
    }

    return context;
  }
}

// src/rbac/decorators/permission.decorator.ts
import { SetMetadata, CustomDecorator } from '@nestjs/common';

export const PERMISSION_KEY = 'permission';

export const Permission = (
  resource: string,
  action: string,
  requireAll: boolean = true,
): CustomDecorator => {
  return SetMetadata(PERMISSION_KEY, { resource, action, requireAll });
};

// src/rbac/decorators/roles.decorator.ts
import { SetMetadata, CustomDecorator } from '@nestjs/common';

export const ROLES_KEY = 'roles';

export const Roles = (...roles: string[]): CustomDecorator => {
  return SetMetadata(ROLES_KEY, roles);
};

// src/rbac/guards/role.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RbacService } from '../rbac.service';

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rbacService: RbacService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const userId = request.user?.userId;

    if (!userId) {
      throw new ForbiddenException('User not authenticated');
    }

    // Get user roles
    const userRoles = await this.rbacService.getUserRoles(userId);
    const userRoleNames = userRoles.map((role) => role.name);

    // Check if user has any of the required roles
    const hasRequiredRole = requiredRoles.some((role) =>
      userRoleNames.includes(role),
    );

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Required roles: ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
```

#### **Usage Example in Controller**

```typescript
// src/users/users.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionGuard } from '../rbac/guards/permission.guard';
import { RoleGuard } from '../rbac/guards/role.guard';
import { Permission } from '../rbac/decorators/permission.decorator';
import { Roles } from '../rbac/decorators/roles.decorator';
import { CreateUserDto, UpdateUserDto } from './dto';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionGuard, RoleGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @Permission('user', 'read')
  @Roles('admin', 'manager')
  async findAll(@Query() query: any) {
    return this.usersService.findAll(query);
  }

  @Get(':id')
  @Permission('user', 'read')
  @Roles('admin', 'manager', 'user')
  async findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Post()
  @Permission('user', 'create')
  @Roles('admin')
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Put(':id')
  @Permission('user', 'update')
  @Roles('admin', 'manager')
  async update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  @Permission('user', 'delete')
  @Roles('admin')
  async remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }

  // Field-level permissions example
  @Get(':id/sensitive')
  @Permission('user', 'read_sensitive')
  @Roles('admin', 'hr')
  async getSensitiveInfo(@Param('id') id: string) {
    const user = await this.usersService.findOne(id);
    
    // The service can apply field-level filtering based on permissions
    return this.usersService.filterSensitiveData(user);
  }
}
```

### 🎯 Real-World Scenario: Healthcare System RBAC
*You're building an EHR (Electronic Health Record) system with strict HIPAA compliance. Different roles (doctor, nurse, receptionist, patient) need different access levels to patient records, with context-based permissions and audit trails.*

**Interview Questions:**
1. How would you design RBAC for HIPAA compliance?
2. What strategies would you implement for emergency access override?
3. How do you handle patient consent for data sharing?
4. What audit logging is required for healthcare systems?
5. How would you implement time-based role assignments (temporary access)?

**Technical Questions:**
1. What's the difference between RBAC and ABAC (Attribute-Based Access Control)?
2. How do you handle permission inheritance in role hierarchies?
3. What are the performance implications of fine-grained permissions?
4. How do you implement row-level security in databases?

---

## 3. CRUD with PostgreSQL & MongoDB

### 📖 In-Depth Explanation

Implementing robust CRUD operations with validation, transactions, and optimization for both SQL (PostgreSQL) and NoSQL (MongoDB) databases.

#### **PostgreSQL CRUD with TypeORM**

```typescript
// src/products/entities/product.entity.ts
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  ManyToOne,
  OneToMany,
  ManyToMany,
  JoinTable,
  Index,
  Check,
  BeforeInsert,
  BeforeUpdate,
  AfterLoad,
} from 'typeorm';
import { Category } from './category.entity';
import { Tag } from './tag.entity';
import { Review } from './review.entity';
import { Inventory } from './inventory.entity';

export enum ProductStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  ARCHIVED = 'archived',
}

export enum ProductType {
  PHYSICAL = 'physical',
  DIGITAL = 'digital',
  SERVICE = 'service',
}

@Entity('products')
@Index(['sku'], { unique: true })
@Index(['categoryId', 'status'])
@Index(['price', 'status'])
@Check(`"price" >= 0`)
@Check(`"stock_quantity" >= 0`)
export class Product {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ length: 100 })
  name: string;

  @Column({ length: 500, nullable: true })
  description: string;

  @Column({ unique: true, length: 50 })
  sku: string;

  @Column('decimal', { precision: 10, scale: 2 })
  price: number;

  @Column('decimal', { precision: 10, scale: 2, nullable: true })
  compareAtPrice: number;

  @Column('decimal', { precision: 5, scale: 2, default: 0 })
  costPrice: number;

  @Column({ default: 0 })
  stockQuantity: number;

  @Column({ default: 0 })
  lowStockThreshold: number;

  @Column({
    type: 'enum',
    enum: ProductStatus,
    default: ProductStatus.DRAFT,
  })
  status: ProductStatus;

  @Column({
    type: 'enum',
    enum: ProductType,
    default: ProductType.PHYSICAL,
  })
  type: ProductType;

  @Column('simple-array', { nullable: true })
  images: string[];

  @Column('jsonb', { nullable: true })
  attributes: Record<string, any>;

  @Column('jsonb', { nullable: true })
  metadata: Record<string, any>;

  @Column({ default: 0 })
  viewCount: number;

  @Column({ default: 0 })
  purchaseCount: number;

  @Column('decimal', { precision: 3, scale: 2, nullable: true })
  averageRating: number;

  @Column({ nullable: true })
  categoryId: string;

  @ManyToOne(() => Category, (category) => category.products, {
    onDelete: 'SET NULL',
  })
  category: Category;

  @OneToMany(() => Review, (review) => review.product)
  reviews: Review[];

  @OneToMany(() => Inventory, (inventory) => inventory.product)
  inventory: Inventory[];

  @ManyToMany(() => Tag, (tag) => tag.products)
  @JoinTable({
    name: 'product_tags',
    joinColumn: { name: 'productId', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'tagId', referencedColumnName: 'id' },
  })
  tags: Tag[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date;

  // Virtual properties
  isOnSale: boolean;
  isLowStock: boolean;
  discountPercentage: number;

  // Lifecycle hooks
  @BeforeInsert()
  @BeforeUpdate()
  validateProduct() {
    if (this.price < 0) {
      throw new Error('Price cannot be negative');
    }

    if (this.compareAtPrice && this.compareAtPrice < this.price) {
      throw new Error('Compare at price cannot be less than price');
    }

    // Generate SKU if not provided
    if (!this.sku) {
      this.sku = this.generateSKU();
    }
  }

  @AfterLoad()
  computeVirtualProperties() {
    this.isOnSale = this.compareAtPrice
      ? this.compareAtPrice > this.price
      : false;

    this.isLowStock = this.stockQuantity <= this.lowStockThreshold;

    if (this.compareAtPrice && this.compareAtPrice > 0) {
      this.discountPercentage = Number(
        (
          ((this.compareAtPrice - this.price) / this.compareAtPrice) *
          100
        ).toFixed(2),
      );
    } else {
      this.discountPercentage = 0;
    }
  }

  private generateSKU(): string {
    const prefix = 'PROD';
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 6);
    return `${prefix}-${timestamp}-${random}`.toUpperCase();
  }

  // Business logic methods
  canPurchase(quantity: number): boolean {
    return (
      this.status === ProductStatus.ACTIVE &&
      this.stockQuantity >= quantity &&
      quantity > 0
    );
  }

  updateStock(quantity: number, type: 'add' | 'subtract'): void {
    if (type === 'add') {
      this.stockQuantity += quantity;
    } else {
      if (this.stockQuantity < quantity) {
        throw new Error('Insufficient stock');
      }
      this.stockQuantity -= quantity;
    }
  }

  updateRating(newRating: number): void {
    const totalReviews = this.reviews?.length || 0;
    const currentTotal = this.averageRating * totalReviews;
    this.averageRating = (currentTotal + newRating) / (totalReviews + 1);
  }
}
```

#### **PostgreSQL Service with Transactions**

```typescript
// src/products/products.service.ts
import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Repository,
  DataSource,
  QueryRunner,
  SelectQueryBuilder,
  FindOptionsWhere,
  In,
  Between,
  Like,
  ILike,
} from 'typeorm';
import { Product, ProductStatus, ProductType } from './entities/product.entity';
import { Category } from './entities/category.entity';
import { Tag } from './entities/tag.entity';
import {
  CreateProductDto,
  UpdateProductDto,
  ProductQueryDto,
  BulkUpdateProductDto,
} from './dto';

interface ProductSearchResult {
  data: Product[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

@Injectable()
export class ProductsService {
  constructor(
    @InjectRepository(Product)
    private readonly productRepository: Repository<Product>,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
    @InjectRepository(Tag)
    private readonly tagRepository: Repository<Tag>,
    private readonly dataSource: DataSource,
  ) {}

  // Create with transaction
  async create(createProductDto: CreateProductDto): Promise<Product> {
    const queryRunner = this.dataSource.createQueryRunner();
    
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Check for duplicate SKU
      const existingProduct = await queryRunner.manager.findOne(Product, {
        where: { sku: createProductDto.sku },
      });

      if (existingProduct) {
        throw new ConflictException('Product with this SKU already exists');
      }

      // Find or create category
      let category: Category | null = null;
      if (createProductDto.categoryId) {
        category = await queryRunner.manager.findOne(Category, {
          where: { id: createProductDto.categoryId },
        });

        if (!category) {
          throw new NotFoundException('Category not found');
        }
      } else if (createProductDto.categoryName) {
        category = await queryRunner.manager.findOne(Category, {
          where: { name: createProductDto.categoryName },
        });

        if (!category) {
          category = queryRunner.manager.create(Category, {
            name: createProductDto.categoryName,
            description: createProductDto.categoryDescription,
          });
          await queryRunner.manager.save(category);
        }
      }

      // Handle tags
      let tags: Tag[] = [];
      if (createProductDto.tagIds && createProductDto.tagIds.length > 0) {
        tags = await queryRunner.manager.find(Tag, {
          where: { id: In(createProductDto.tagIds) },
        });

        if (tags.length !== createProductDto.tagIds.length) {
          throw new NotFoundException('Some tags not found');
        }
      } else if (createProductDto.tagNames) {
        const tagPromises = createProductDto.tagNames.map(async (tagName) => {
          let tag = await queryRunner.manager.findOne(Tag, {
            where: { name: tagName },
          });

          if (!tag) {
            tag = queryRunner.manager.create(Tag, { name: tagName });
            await queryRunner.manager.save(tag);
          }

          return tag;
        });

        tags = await Promise.all(tagPromises);
      }

      // Create product
      const product = queryRunner.manager.create(Product, {
        ...createProductDto,
        category,
        tags,
      });

      const savedProduct = await queryRunner.manager.save(product);

      await queryRunner.commitTransaction();

      // Return with relations
      return this.productRepository.findOne({
        where: { id: savedProduct.id },
        relations: ['category', 'tags'],
      });
    } catch (error) {
      await queryRunner.rollbackTransaction();
      
      if (
        error instanceof ConflictException ||
        error instanceof NotFoundException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      
      throw new InternalServerErrorException('Failed to create product');
    } finally {
      await queryRunner.release();
    }
  }

  // Advanced search with filtering, sorting, and pagination
  async findAll(queryDto: ProductQueryDto): Promise<ProductSearchResult> {
    const {
      page = 1,
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'DESC',
      search,
      status,
      type,
      categoryId,
      minPrice,
      maxPrice,
      tags,
      inStock,
      onSale,
    } = queryDto;

    const skip = (page - 1) * limit;

    // Build query
    const queryBuilder = this.productRepository
      .createQueryBuilder('product')
      .leftJoinAndSelect('product.category', 'category')
      .leftJoinAndSelect('product.tags', 'tags')
      .where('product.deletedAt IS NULL');

    // Apply filters
    this.applyFilters(queryBuilder, {
      search,
      status,
      type,
      categoryId,
      minPrice,
      maxPrice,
      tags,
      inStock,
      onSale,
    });

    // Get total count before pagination
    const total = await queryBuilder.getCount();

    // Apply sorting
    if (sortBy === 'price') {
      queryBuilder.orderBy('product.price', sortOrder);
    } else if (sortBy === 'name') {
      queryBuilder.orderBy('product.name', sortOrder);
    } else if (sortBy === 'rating') {
      queryBuilder.orderBy('product.averageRating', sortOrder);
    } else {
      queryBuilder.orderBy(`product.${sortBy}`, sortOrder);
    }

    // Apply pagination
    queryBuilder.skip(skip).take(limit);

    // Execute query
    const data = await queryBuilder.getMany();

    // Calculate pagination metadata
    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrevious = page > 1;

    return {
      data,
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages,
      hasNext,
      hasPrevious,
    };
  }

  private applyFilters(
    queryBuilder: SelectQueryBuilder<Product>,
    filters: {
      search?: string;
      status?: ProductStatus;
      type?: ProductType;
      categoryId?: string;
      minPrice?: number;
      maxPrice?: number;
      tags?: string[];
      inStock?: boolean;
      onSale?: boolean;
    },
  ) {
    const {
      search,
      status,
      type,
      categoryId,
      minPrice,
      maxPrice,
      tags,
      inStock,
      onSale,
    } = filters;

    if (search) {
      queryBuilder.andWhere(
        '(product.name ILIKE :search OR product.description ILIKE :search OR product.sku ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    if (status) {
      queryBuilder.andWhere('product.status = :status', { status });
    }

    if (type) {
      queryBuilder.andWhere('product.type = :type', { type });
    }

    if (categoryId) {
      queryBuilder.andWhere('product.categoryId = :categoryId', { categoryId });
    }

    if (minPrice !== undefined) {
      queryBuilder.andWhere('product.price >= :minPrice', { minPrice });
    }

    if (maxPrice !== undefined) {
      queryBuilder.andWhere('product.price <= :maxPrice', { maxPrice });
    }

    if (tags && tags.length > 0) {
      queryBuilder
        .innerJoin('product.tags', 'filterTags')
        .andWhere('filterTags.id IN (:...tags)', { tags });
    }

    if (inStock !== undefined) {
      if (inStock) {
        queryBuilder.andWhere('product.stockQuantity > 0');
      } else {
        queryBuilder.andWhere('product.stockQuantity = 0');
      }
    }

    if (onSale !== undefined) {
      if (onSale) {
        queryBuilder.andWhere('product.compareAtPrice IS NOT NULL');
        queryBuilder.andWhere('product.compareAtPrice > product.price');
      }
    }
  }

  // Find by ID with caching
  async findOne(id: string): Promise<Product> {
    const product = await this.productRepository.findOne({
      where: { id, deletedAt: null },
      relations: ['category', 'tags', 'reviews', 'inventory'],
    });

    if (!product) {
      throw new NotFoundException('Product not found');
    }

    // Increment view count (fire and forget)
    this.incrementViewCount(id).catch(console.error);

    return product;
  }

  // Update with optimistic locking
  async update(
    id: string,
    updateProductDto: UpdateProductDto,
  ): Promise<Product> {
    const queryRunner = this.dataSource.createQueryRunner();
    
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Lock the row for update
      const product = await queryRunner.manager.findOne(Product, {
        where: { id, deletedAt: null },
        lock: { mode: 'pessimistic_write' },
      });

      if (!product) {
        throw new NotFoundException('Product not found');
      }

      // Check version if using optimistic locking
      if (updateProductDto.version && product.version !== updateProductDto.version) {
        throw new ConflictException('Product has been modified by another user');
      }

      // Update fields
      Object.assign(product, updateProductDto);

      // Handle category update if provided
      if (updateProductDto.categoryId) {
        const category = await queryRunner.manager.findOne(Category, {
          where: { id: updateProductDto.categoryId },
        });

        if (!category) {
          throw new NotFoundException('Category not found');
        }

        product.category = category;
      }

      // Handle tags update if provided
      if (updateProductDto.tagIds) {
        const tags = await queryRunner.manager.find(Tag, {
          where: { id: In(updateProductDto.tagIds) },
        });

        if (tags.length !== updateProductDto.tagIds.length) {
          throw new NotFoundException('Some tags not found');
        }

        product.tags = tags;
      }

      // Save updated product
      const updatedProduct = await queryRunner.manager.save(product);

      await queryRunner.commitTransaction();

      return this.productRepository.findOne({
        where: { id: updatedProduct.id },
        relations: ['category', 'tags'],
      });
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Soft delete with cascade
  async remove(id: string): Promise<void> {
    const product = await this.productRepository.findOne({
      where: { id, deletedAt: null },
    });

    if (!product) {
      throw new NotFoundException('Product not found');
    }

    // Check if product can be deleted (e.g., has orders)
    const hasOrders = await this.checkProductHasOrders(id);
    if (hasOrders) {
      throw new BadRequestException(
        'Cannot delete product with existing orders',
      );
    }

    // Soft delete
    await this.productRepository.softDelete(id);
  }

  // Bulk operations
  async bulkUpdate(
    bulkUpdateDto: BulkUpdateProductDto,
  ): Promise<{ updated: number; failed: number }> {
    const { productIds, updates } = bulkUpdateDto;
    
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    let updated = 0;
    const failed: Array<{ id: string; error: string }> = [];

    try {
      for (const productId of productIds) {
        try {
          const product = await queryRunner.manager.findOne(Product, {
            where: { id: productId, deletedAt: null },
          });

          if (!product) {
            failed.push({ id: productId, error: 'Product not found' });
            continue;
          }

          // Apply updates
          Object.assign(product, updates);
          await queryRunner.manager.save(product);
          updated++;
        } catch (error) {
          failed.push({ id: productId, error: error.message });
        }
      }

      await queryRunner.commitTransaction();
      return { updated, failed: failed.length };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Stock management
  async updateStock(
    productId: string,
    quantity: number,
    action: 'add' | 'subtract',
    reason?: string,
  ): Promise<Product> {
    const queryRunner = this.dataSource.createQueryRunner();
    
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const product = await queryRunner.manager.findOne(Product, {
        where: { id: productId, deletedAt: null },
        lock: { mode: 'pessimistic_write' },
      });

      if (!product) {
        throw new NotFoundException('Product not found');
      }

      // Update stock
      if (action === 'add') {
        product.stockQuantity += quantity;
      } else {
        if (product.stockQuantity < quantity) {
          throw new BadRequestException('Insufficient stock');
        }
        product.stockQuantity -= quantity;
      }

      // Create inventory record
      const inventory = queryRunner.manager.create(Inventory, {
        productId,
        quantity: action === 'add' ? quantity : -quantity,
        type: action === 'add' ? 'restock' : 'sale',
        reason,
        previousQuantity: product.stockQuantity - (action === 'add' ? quantity : -quantity),
        newQuantity: product.stockQuantity,
      });

      await queryRunner.manager.save([product, inventory]);
      await queryRunner.commitTransaction();

      return product;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Analytics and reporting
  async getProductAnalytics(timeRange: 'day' | 'week' | 'month' | 'year') {
    const date = new Date();
    let startDate: Date;

    switch (timeRange) {
      case 'day':
        startDate = new Date(date.setDate(date.getDate() - 1));
        break;
      case 'week':
        startDate = new Date(date.setDate(date.getDate() - 7));
        break;
      case 'month':
        startDate = new Date(date.setMonth(date.getMonth() - 1));
        break;
      case 'year':
        startDate = new Date(date.setFullYear(date.getFullYear() - 1));
        break;
      default:
        startDate = new Date(date.setDate(date.getDate() - 7));
    }

    return this.productRepository
      .createQueryBuilder('product')
      .select([
        'product.id',
        'product.name',
        'product.sku',
        'COUNT(reviews.id) as reviewCount',
        'AVG(reviews.rating) as averageRating',
        'SUM(CASE WHEN inventory.type = :sale THEN -inventory.quantity ELSE 0 END) as unitsSold',
        'SUM(CASE WHEN inventory.type = :sale THEN product.price * -inventory.quantity ELSE 0 END) as revenue',
      ])
      .leftJoin('product.reviews', 'reviews')
      .leftJoin('product.inventory', 'inventory', 'inventory.createdAt >= :startDate', {
        startDate,
      })
      .where('product.deletedAt IS NULL')
      .andWhere('product.status = :status', { status: ProductStatus.ACTIVE })
      .setParameter('sale', 'sale')
      .groupBy('product.id')
      .orderBy('revenue', 'DESC')
      .limit(10)
      .getRawMany();
  }

  // Utility methods
  private async incrementViewCount(productId: string): Promise<void> {
    await this.productRepository.increment(
      { id: productId },
      'viewCount',
      1,
    );
  }

  private async checkProductHasOrders(productId: string): Promise<boolean> {
    // Implementation depends on your order system
    // This is a placeholder
    return false;
  }

  // Search with full-text search (PostgreSQL tsvector)
  async searchFullText(query: string): Promise<Product[]> {
    return this.productRepository
      .createQueryBuilder('product')
      .where(
        `to_tsvector('english', coalesce(product.name, '') || ' ' || coalesce(product.description, '')) @@ to_tsquery(:query)`,
        { query: `${query.replace(/\s+/g, ' & ')}:*` },
      )
      .andWhere('product.deletedAt IS NULL')
      .andWhere('product.status = :status', { status: ProductStatus.ACTIVE })
      .orderBy(
        `ts_rank(to_tsvector('english', coalesce(product.name, '') || ' ' || coalesce(product.description, '')), to_tsquery(:query))`,
        'DESC',
      )
      .limit(50)
      .getMany();
  }
}
```

#### **MongoDB CRUD with Mongoose**

```typescript
// src/orders/schemas/order.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types, Schema as MongooseSchema } from 'mongoose';
import { User } from '../../users/schemas/user.schema';
import { Product } from '../../products/schemas/product.schema';

export enum OrderStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  PROCESSING = 'processing',
  SHIPPED = 'shipped',
  DELIVERED = 'delivered',
  CANCELLED = 'cancelled',
  REFUNDED = 'refunded',
}

export enum PaymentStatus {
  PENDING = 'pending',
  PAID = 'paid',
  FAILED = 'failed',
  REFUNDED = 'refunded',
}

export enum PaymentMethod {
  CREDIT_CARD = 'credit_card',
  DEBIT_CARD = 'debit_card',
  PAYPAL = 'paypal',
  BANK_TRANSFER = 'bank_transfer',
  CASH_ON_DELIVERY = 'cash_on_delivery',
}

@Schema({
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: (doc, ret) => {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  },
})
export class Order extends Document {
  @Prop({ required: true, unique: true, index: true })
  orderNumber: string;

  @Prop({ type: Types.ObjectId, ref: 'User', required: true, index: true })
  userId: Types.ObjectId;

  @Prop({ type: Types.ObjectId, ref: 'User' })
  customer?: User;

  @Prop([
    {
      productId: { type: Types.ObjectId, ref: 'Product', required: true },
      name: { type: String, required: true },
      sku: { type: String, required: true },
      price: { type: Number, required: true, min: 0 },
      quantity: { type: Number, required: true, min: 1 },
      subtotal: { type: Number, required: true },
      attributes: { type: MongooseSchema.Types.Mixed },
    },
  ])
  items: Array<{
    productId: Types.ObjectId;
    name: string;
    sku: string;
    price: number;
    quantity: number;
    subtotal: number;
    attributes?: Record<string, any>;
  }>;

  @Prop({
    type: String,
    enum: OrderStatus,
    default: OrderStatus.PENDING,
    index: true,
  })
  status: OrderStatus;

  @Prop({
    type: String,
    enum: PaymentStatus,
    default: PaymentStatus.PENDING,
    index: true,
  })
  paymentStatus: PaymentStatus;

  @Prop({
    type: String,
    enum: PaymentMethod,
    required: true,
  })
  paymentMethod: PaymentMethod;

  @Prop()
  paymentId?: string;

  @Prop({ type: MongooseSchema.Types.Mixed })
  paymentDetails?: Record<string, any>;

  @Prop({ required: true, min: 0 })
  subtotal: number;

  @Prop({ default: 0, min: 0 })
  taxAmount: number;

  @Prop({ default: 0, min: 0 })
  shippingAmount: number;

  @Prop({ default: 0, min: 0 })
  discountAmount: number;

  @Prop({ required: true, min: 0 })
  total: number;

  @Prop({
    shippingAddress: {
      street: { type: String, required: true },
      city: { type: String, required: true },
      state: { type: String, required: true },
      country: { type: String, required: true },
      zipCode: { type: String, required: true },
      phone: { type: String },
    },
    billingAddress: {
      street: { type: String, required: true },
      city: { type: String, required: true },
      state: { type: String, required: true },
      country: { type: String, required: true },
      zipCode: { type: String, required: true },
    },
  })
  address: {
    shippingAddress: {
      street: string;
      city: string;
      state: string;
      country: string;
      zipCode: string;
      phone?: string;
    };
    billingAddress: {
      street: string;
      city: string;
      state: string;
      country: string;
      zipCode: string;
    };
  };

  @Prop()
  notes?: string;

  @Prop()
  trackingNumber?: string;

  @Prop()
  estimatedDelivery?: Date;

  @Prop()
  deliveredAt?: Date;

  @Prop()
  cancelledAt?: Date;

  @Prop()
  cancelledReason?: string;

  @Prop({ type: MongooseSchema.Types.Mixed })
  metadata?: Record<string, any>;

  // Virtuals
  itemCount?: number;
  isDelivered?: boolean;
  isCancelled?: boolean;
  daysSinceCreated?: number;

  // Methods
  calculateTotals(): void;
  canBeCancelled(): boolean;
  updateStatus(newStatus: OrderStatus): void;
}

export const OrderSchema = SchemaFactory.createForClass(Order);

// Virtuals
OrderSchema.virtual('itemCount').get(function () {
  return this.items.reduce((sum, item) => sum + item.quantity, 0);
});

OrderSchema.virtual('isDelivered').get(function () {
  return this.status === OrderStatus.DELIVERED;
});

OrderSchema.virtual('isCancelled').get(function () {
  return this.status === OrderStatus.CANCELLED;
});

OrderSchema.virtual('daysSinceCreated').get(function () {
  const diff = new Date().getTime() - this.createdAt.getTime();
  return Math.floor(diff / (1000 * 60 * 60 * 24));
});

// Methods
OrderSchema.methods.calculateTotals = function () {
  this.subtotal = this.items.reduce(
    (sum, item) => sum + item.price * item.quantity,
    0,
  );

  this.total = this.subtotal + this.taxAmount + this.shippingAmount - this.discountAmount;
};

OrderSchema.methods.canBeCancelled = function () {
  const nonCancellableStatuses = [
    OrderStatus.SHIPPED,
    OrderStatus.DELIVERED,
    OrderStatus.CANCELLED,
    OrderStatus.REFUNDED,
  ];
  return !nonCancellableStatuses.includes(this.status);
};

OrderSchema.methods.updateStatus = function (newStatus: OrderStatus) {
  const validTransitions: Record<OrderStatus, OrderStatus[]> = {
    [OrderStatus.PENDING]: [OrderStatus.CONFIRMED, OrderStatus.CANCELLED],
    [OrderStatus.CONFIRMED]: [OrderStatus.PROCESSING, OrderStatus.CANCELLED],
    [OrderStatus.PROCESSING]: [OrderStatus.SHIPPED, OrderStatus.CANCELLED],
    [OrderStatus.SHIPPED]: [OrderStatus.DELIVERED],
    [OrderStatus.DELIVERED]: [OrderStatus.REFUNDED],
    [OrderStatus.CANCELLED]: [],
    [OrderStatus.REFUNDED]: [],
  };

  if (!validTransitions[this.status].includes(newStatus)) {
    throw new Error(`Invalid status transition from ${this.status} to ${newStatus}`);
  }

  this.status = newStatus;

  // Set timestamps
  if (newStatus === OrderStatus.DELIVERED) {
    this.deliveredAt = new Date();
  } else if (newStatus === OrderStatus.CANCELLED) {
    this.cancelledAt = new Date();
  }
};

// Indexes
OrderSchema.index({ createdAt: -1 });
OrderSchema.index({ userId: 1, createdAt: -1 });
OrderSchema.index({ status: 1, paymentStatus: 1 });
OrderSchema.index({ 'items.productId': 1 });
OrderSchema.index({ orderNumber: 'text', 'items.name': 'text' });

// Pre-save middleware
OrderSchema.pre('save', function (next) {
  if (this.isModified('items') || this.isModified('taxAmount') || 
      this.isModified('shippingAmount') || this.isModified('discountAmount')) {
    this.calculateTotals();
  }

  // Generate order number if not present
  if (!this.orderNumber) {
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 1000);
    this.orderNumber = `ORD-${timestamp}-${random}`;
  }

  next();
});
```

#### **MongoDB Service with Aggregation**

```typescript
// src/orders/orders.service.ts
import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types, ClientSession } from 'mongoose';
import { Order, OrderStatus, PaymentStatus } from './schemas/order.schema';
import { Product } from '../products/schemas/product.schema';
import { CreateOrderDto, UpdateOrderDto, OrderQueryDto } from './dto';

interface OrderStats {
  totalOrders: number;
  totalRevenue: number;
  averageOrderValue: number;
  ordersByStatus: Record<OrderStatus, number>;
  revenueByMonth: Array<{ month: string; revenue: number }>;
  topProducts: Array<{ productId: string; name: string; quantity: number }>;
}

@Injectable()
export class OrdersService {
  constructor(
    @InjectModel(Order.name) private readonly orderModel: Model<Order>,
    @InjectModel(Product.name) private readonly productModel: Model<Product>,
  ) {}

  // Create order with transaction
  async create(createOrderDto: CreateOrderDto, userId: string): Promise<Order> {
    const session = await this.orderModel.db.startSession();
    
    try {
      session.startTransaction();

      // Validate products and check stock
      const productIds = createOrderDto.items.map((item) => item.productId);
      const products = await this.productModel
        .find({ _id: { $in: productIds } })
        .session(session);

      if (products.length !== productIds.length) {
        throw new NotFoundException('Some products not found');
      }

      // Prepare order items and check stock
      const orderItems = [];
      const stockUpdates = [];

      for (const item of createOrderDto.items) {
        const product = products.find(
          (p) => p._id.toString() === item.productId,
        );

        if (!product) {
          throw new NotFoundException(`Product ${item.productId} not found`);
        }

        if (product.stockQuantity < item.quantity) {
          throw new BadRequestException(
            `Insufficient stock for product ${product.name}`,
          );
        }

        orderItems.push({
          productId: product._id,
          name: product.name,
          sku: product.sku,
          price: product.price,
          quantity: item.quantity,
          subtotal: product.price * item.quantity,
          attributes: item.attributes,
        });

        // Prepare stock update
        stockUpdates.push({
          updateOne: {
            filter: { _id: product._id },
            update: { $inc: { stockQuantity: -item.quantity } },
          },
        });
      }

      // Calculate totals
      const subtotal = orderItems.reduce((sum, item) => sum + item.subtotal, 0);
      const total =
        subtotal +
        (createOrderDto.taxAmount || 0) +
        (createOrderDto.shippingAmount || 0) -
        (createOrderDto.discountAmount || 0);

      // Create order
      const order = new this.orderModel({
        ...createOrderDto,
        userId: new Types.ObjectId(userId),
        items: orderItems,
        subtotal,
        total,
        status: OrderStatus.PENDING,
        paymentStatus: PaymentStatus.PENDING,
      });

      // Execute updates in parallel
      await Promise.all([
        order.save({ session }),
        this.productModel.bulkWrite(stockUpdates, { session }),
      ]);

      await session.commitTransaction();

      // Populate customer and products
      const populatedOrder = await this.orderModel
        .findById(order._id)
        .populate('customer', 'name email phone')
        .populate('items.productId', 'name images')
        .lean();

      return populatedOrder;
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // Advanced search with aggregation
  async findAll(queryDto: OrderQueryDto) {
    const {
      page = 1,
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      status,
      paymentStatus,
      userId,
      startDate,
      endDate,
      minTotal,
      maxTotal,
      search,
    } = queryDto;

    const skip = (page - 1) * limit;
    const sortDirection = sortOrder === 'desc' ? -1 : 1;

    // Build match conditions
    const matchConditions: any = {};

    if (status) {
      matchConditions.status = status;
    }

    if (paymentStatus) {
      matchConditions.paymentStatus = paymentStatus;
    }

    if (userId) {
      matchConditions.userId = new Types.ObjectId(userId);
    }

    if (startDate || endDate) {
      matchConditions.createdAt = {};
      if (startDate) {
        matchConditions.createdAt.$gte = new Date(startDate);
      }
      if (endDate) {
        matchConditions.createdAt.$lte = new Date(endDate);
      }
    }

    if (minTotal !== undefined || maxTotal !== undefined) {
      matchConditions.total = {};
      if (minTotal !== undefined) {
        matchConditions.total.$gte = minTotal;
      }
      if (maxTotal !== undefined) {
        matchConditions.total.$lte = maxTotal;
      }
    }

    if (search) {
      matchConditions.$or = [
        { orderNumber: { $regex: search, $options: 'i' } },
        { 'items.name': { $regex: search, $options: 'i' } },
        { 'address.shippingAddress.city': { $regex: search, $options: 'i' } },
      ];
    }

    // Aggregation pipeline
    const pipeline = [
      { $match: matchConditions },
      {
        $lookup: {
          from: 'users',
          localField: 'userId',
          foreignField: '_id',
          as: 'customer',
        },
      },
      { $unwind: { path: '$customer', preserveNullAndEmptyArrays: true } },
      {
        $lookup: {
          from: 'products',
          localField: 'items.productId',
          foreignField: '_id',
          as: 'productDetails',
        },
      },
      {
        $addFields: {
          itemCount: { $sum: '$items.quantity' },
          customerName: '$customer.name',
          customerEmail: '$customer.email',
        },
      },
      {
        $project: {
          'customer.password': 0,
          'customer.__v': 0,
          'productDetails.__v': 0,
        },
      },
      { $sort: { [sortBy]: sortDirection } },
      {
        $facet: {
          metadata: [{ $count: 'total' }, { $addFields: { page, limit } }],
          data: [{ $skip: skip }, { $limit: limit }],
        },
      },
    ];

    const [result] = await this.orderModel.aggregate(pipeline).exec();

    const total = result.metadata[0]?.total || 0;
    const data = result.data || [];

    const totalPages = Math.ceil(total / limit);
    const hasNext = page < totalPages;
    const hasPrevious = page > 1;

    return {
      data,
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages,
      hasNext,
      hasPrevious,
    };
  }

  // Find by ID with population
  async findOne(id: string): Promise<Order> {
    const order = await this.orderModel
      .findById(id)
      .populate('customer', 'name email phone')
      .populate('items.productId', 'name images price sku')
      .lean();

    if (!order) {
      throw new NotFoundException('Order not found');
    }

    return order;
  }

  // Update order status with validation
  async updateStatus(
    id: string,
    status: OrderStatus,
    notes?: string,
  ): Promise<Order> {
    const order = await this.orderModel.findById(id);

    if (!order) {
      throw new NotFoundException('Order not found');
    }

    try {
      order.updateStatus(status);
      
      if (notes) {
        order.notes = order.notes ? `${order.notes}\n${notes}` : notes;
      }

      await order.save();

      // If cancelled, restore stock
      if (status === OrderStatus.CANCELLED) {
        await this.restoreStock(order);
      }

      return order;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  // Analytics with aggregation
  async getOrderStats(timeRange: 'day' | 'week' | 'month' | 'year'): Promise<OrderStats> {
    const date = new Date();
    let startDate: Date;

    switch (timeRange) {
      case 'day':
        startDate = new Date(date.setDate(date.getDate() - 1));
        break;
      case 'week':
        startDate = new Date(date.setDate(date.getDate() - 7));
        break;
      case 'month':
        startDate = new Date(date.setMonth(date.getMonth() - 1));
        break;
      case 'year':
        startDate = new Date(date.setFullYear(date.getFullYear() - 1));
        break;
      default:
        startDate = new Date(date.setDate(date.getDate() - 30));
    }

    const pipeline = [
      {
        $match: {
          createdAt: { $gte: startDate },
          status: { $ne: OrderStatus.CANCELLED },
        },
      },
      {
        $facet: {
          // Total orders and revenue
          summary: [
            {
              $group: {
                _id: null,
                totalOrders: { $sum: 1 },
                totalRevenue: { $sum: '$total' },
                avgOrderValue: { $avg: '$total' },
              },
            },
          ],
          // Orders by status
          byStatus: [
            {
              $group: {
                _id: '$status',
                count: { $sum: 1 },
                revenue: { $sum: '$total' },
              },
            },
          ],
          // Revenue by month
          revenueByMonth: [
            {
              $group: {
                _id: {
                  year: { $year: '$createdAt' },
                  month: { $month: '$createdAt' },
                },
                revenue: { $sum: '$total' },
                orders: { $sum: 1 },
              },
            },
            { $sort: { '_id.year': -1, '_id.month': -1 } },
            { $limit: 12 },
          ],
          // Top products
          topProducts: [
            { $unwind: '$items' },
            {
              $group: {
                _id: '$items.productId',
                name: { $first: '$items.name' },
                quantity: { $sum: '$items.quantity' },
                revenue: { $sum: { $multiply: ['$items.price', '$items.quantity'] } },
              },
            },
            { $sort: { quantity: -1 } },
            { $limit: 10 },
          ],
        },
      },
    ];

    const [result] = await this.orderModel.aggregate(pipeline).exec();

    const summary = result.summary[0] || {
      totalOrders: 0,
      totalRevenue: 0,
      avgOrderValue: 0,
    };

    const ordersByStatus = {};
    result.byStatus.forEach((item) => {
      ordersByStatus[item._id] = item.count;
    });

    const revenueByMonth = result.revenueByMonth.map((item) => ({
      month: `${item._id.year}-${item._id.month.toString().padStart(2, '0')}`,
      revenue: item.revenue,
      orders: item.orders,
    }));

    const topProducts = result.topProducts.map((item) => ({
      productId: item._id.toString(),
      name: item.name,
      quantity: item.quantity,
      revenue: item.revenue,
    }));

    return {
      totalOrders: summary.totalOrders,
      totalRevenue: summary.totalRevenue,
      averageOrderValue: summary.avgOrderValue,
      ordersByStatus,
      revenueByMonth,
      topProducts,
    };
  }

  // Bulk operations
  async bulkUpdateStatus(
    orderIds: string[],
    status: OrderStatus,
  ): Promise<{ updated: number; failed: number }> {
    const session = await this.orderModel.db.startSession();
    
    try {
      session.startTransaction();

      let updated = 0;
      const failed: Array<{ id: string; error: string }> = [];

      for (const orderId of orderIds) {
        try {
          const order = await this.orderModel.findById(orderId).session(session);

          if (!order) {
            failed.push({ id: orderId, error: 'Order not found' });
            continue;
          }

          order.updateStatus(status);
          await order.save({ session });
          updated++;

          // Restore stock if cancelled
          if (status === OrderStatus.CANCELLED) {
            await this.restoreStock(order, session);
          }
        } catch (error) {
          failed.push({ id: orderId, error: error.message });
        }
      }

      await session.commitTransaction();
      return { updated, failed: failed.length };
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // Search with text index
  async searchOrders(query: string, limit: number = 50): Promise<Order[]> {
    return this.orderModel
      .find(
        { $text: { $search: query } },
        { score: { $meta: 'textScore' } },
      )
      .sort({ score: { $meta: 'textScore' } })
      .limit(limit)
      .populate('customer', 'name email')
      .lean();
  }

  // Helper methods
  private async restoreStock(order: Order, session?: ClientSession) {
    const stockUpdates = order.items.map((item) => ({
      updateOne: {
        filter: { _id: item.productId },
        update: { $inc: { stockQuantity: item.quantity } },
      },
    }));

    const options = session ? { session } : {};
    await this.productModel.bulkWrite(stockUpdates, options);
  }

  // Generate report
  async generateSalesReport(startDate: Date, endDate: Date) {
    const pipeline = [
      {
        $match: {
          createdAt: { $gte: startDate, $lte: endDate },
          status: { $ne: OrderStatus.CANCELLED },
        },
      },
      { $unwind: '$items' },
      {
        $group: {
          _id: {
            productId: '$items.productId',
            date: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' },
            },
          },
          productName: { $first: '$items.name' },
          sku: { $first: '$items.sku' },
          quantity: { $sum: '$items.quantity' },
          revenue: { $sum: { $multiply: ['$items.price', '$items.quantity'] } },
          orders: { $addToSet: '$_id' },
        },
      },
      {
        $group: {
          _id: '$_id.productId',
          productName: { $first: '$productName' },
          sku: { $first: '$sku' },
          totalQuantity: { $sum: '$quantity' },
          totalRevenue: { $sum: '$revenue' },
          dailySales: {
            $push: {
              date: '$_id.date',
              quantity: '$quantity',
              revenue: '$revenue',
              orders: { $size: '$orders' },
            },
          },
        },
      },
      { $sort: { totalRevenue: -1 } },
    ];

    return this.orderModel.aggregate(pipeline).exec();
  }
}
```

### 🎯 Real-World Scenario: E-commerce Platform with 1M+ Products
*You're building an e-commerce platform with 1 million+ products, complex filtering, full-text search, real-time inventory updates, and high concurrency requirements. You need to support both SQL and NoSQL approaches.*

**Interview Questions:**
1. How would you design the database schema for 1M+ products with complex relationships?
2. What strategies would you implement for search performance optimization?
3. How do you handle inventory management with high concurrency?
4. What caching strategies would you use for product listings?
5. How would you implement real-time price updates across multiple regions?

**Technical Questions:**
1. What are the trade-offs between PostgreSQL and MongoDB for e-commerce?
2. How do you implement full-text search in both databases?
3. What are the best practices for database transactions in high-concurrency systems?
4. How do you handle database migrations for large datasets?

---

## 4. File Uploads

### 📖 In-Depth Explanation

Comprehensive file upload system with validation, processing, CDN integration, and security features.

#### **Complete File Upload Service**

```typescript
// src/file-upload/file-upload.service.ts
import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createHash } from 'crypto';
import { promisify } from 'util';
import { pipeline, Readable } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import * as sharp from 'sharp';
import * as ffmpeg from 'fluent-ffmpeg';
import { FileTypeValidator, MaxFileSizeValidator } from '@nestjs/common';
import { MulterOptions } from '@nestjs/platform-express/multer/interfaces/multer-options.interface';

export enum FileType {
  IMAGE = 'image',
  VIDEO = 'video',
  DOCUMENT = 'document',
  AUDIO = 'audio',
  ARCHIVE = 'archive',
  OTHER = 'other',
}

export enum FileStatus {
  UPLOADING = 'uploading',
  PROCESSING = 'processing',
  READY = 'ready',
  FAILED = 'failed',
  DELETED = 'deleted',
}

interface FileMetadata {
  originalName: string;
  mimeType: string;
  size: number;
  width?: number;
  height?: number;
  duration?: number;
  encoding?: string;
  hash: string;
}

interface UploadOptions {
  maxSize?: number;
  allowedTypes?: string[];
  generateThumbnail?: boolean;
  optimizeImage?: boolean;
  compressVideo?: boolean;
  watermark?: boolean;
  expirationHours?: number;
  private?: boolean;
  tags?: Record<string, string>;
}

@Injectable()
export class FileUploadService {
  private s3Client: S3Client;
  private readonly uploadDir: string;
  private readonly maxFileSize: number;
  private readonly allowedMimeTypes: Record<FileType, string[]>;

  constructor(private readonly configService: ConfigService) {
    this.s3Client = new S3Client({
      region: this.configService.get('AWS_REGION'),
      credentials: {
        accessKeyId: this.configService.get('AWS_ACCESS_KEY_ID'),
        secretAccessKey: this.configService.get('AWS_SECRET_ACCESS_KEY'),
      },
    });

    this.uploadDir = this.configService.get('UPLOAD_DIR', './uploads');
    this.maxFileSize = 100 * 1024 * 1024; // 100MB

    this.allowedMimeTypes = {
      [FileType.IMAGE]: [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/svg+xml',
      ],
      [FileType.VIDEO]: [
        'video/mp4',
        'video/mpeg',
        'video/ogg',
        'video/webm',
        'video/quicktime',
      ],
      [FileType.DOCUMENT]: [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain',
        'text/csv',
      ],
      [FileType.AUDIO]: [
        'audio/mpeg',
        'audio/wav',
        'audio/ogg',
        'audio/webm',
      ],
      [FileType.ARCHIVE]: [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-tar',
        'application/gzip',
      ],
      [FileType.OTHER]: [],
    };

    // Ensure upload directory exists
    if (!fs.existsSync(this.uploadDir)) {
      fs.mkdirSync(this.uploadDir, { recursive: true });
    }
  }

  // Get Multer configuration
  getMulterOptions(options?: UploadOptions): MulterOptions {
    const maxSize = options?.maxSize || this.maxFileSize;
    const allowedTypes = options?.allowedTypes || Object.values(this.allowedMimeTypes).flat();

    return {
      dest: this.uploadDir,
      limits: {
        fileSize: maxSize,
        files: options?.private ? 1 : 10, // Limit files per request
      },
      fileFilter: (req, file, callback) => {
        this.validateFile(file, allowedTypes, maxSize)
          .then(() => callback(null, true))
          .catch((error) => callback(error, false));
      },
      storage: this.createStorageEngine(),
    };
  }

  // Main upload method
  async uploadFile(
    file: Express.Multer.File,
    userId: string,
    options: UploadOptions = {},
  ): Promise<{
    fileId: string;
    url: string;
    thumbnailUrl?: string;
    metadata: FileMetadata;
    status: FileStatus;
  }> {
    try {
      // Validate file
      await this.validateFile(file, options.allowedTypes, options.maxSize);

      // Generate file hash
      const hash = await this.generateFileHash(file.path);

      // Check for duplicate files
      const existingFile = await this.findDuplicateFile(hash, userId);
      if (existingFile && !options.private) {
        // Return existing file instead of uploading again
        return {
          fileId: existingFile.id,
          url: existingFile.url,
          thumbnailUrl: existingFile.thumbnailUrl,
          metadata: existingFile.metadata,
          status: FileStatus.READY,
        };
      }

      // Determine file type
      const fileType = this.getFileType(file.mimetype);
      const fileId = this.generateFileId(userId, fileType);

      // Process file based on type
      const processedFile = await this.processFile(file, fileType, options);

      // Upload to storage (S3 or local)
      const uploadResult = await this.uploadToStorage(
        processedFile,
        fileId,
        options,
      );

      // Generate thumbnail if needed
      let thumbnailUrl: string | undefined;
      if (options.generateThumbnail && this.canGenerateThumbnail(fileType)) {
        thumbnailUrl = await this.generateThumbnail(processedFile, fileId);
      }

      // Extract metadata
      const metadata = await this.extractMetadata(processedFile, file);

      // Save file record to database
      const fileRecord = await this.saveFileRecord({
        id: fileId,
        userId,
        originalName: file.originalname,
        fileName: uploadResult.fileName,
        url: uploadResult.url,
        thumbnailUrl,
        type: fileType,
        status: FileStatus.READY,
        metadata,
        size: file.size,
        mimeType: file.mimetype,
        isPrivate: options.private || false,
        tags: options.tags,
        expirationDate: options.expirationHours
          ? new Date(Date.now() + options.expirationHours * 60 * 60 * 1000)
          : null,
      });

      // Clean up local file
      await this.cleanupLocalFile(processedFile.path);

      return {
        fileId: fileRecord.id,
        url: fileRecord.url,
        thumbnailUrl: fileRecord.thumbnailUrl,
        metadata: fileRecord.metadata,
        status: fileRecord.status,
      };
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to upload file: ${error.message}`,
      );
    }
  }

  // Multipart upload for large files
  async initiateMultipartUpload(
    fileName: string,
    fileType: string,
    userId: string,
    options: UploadOptions = {},
  ): Promise<{
    uploadId: string;
    fileId: string;
    partSize: number;
    urls: string[];
  }> {
    const fileTypeEnum = this.getFileType(fileType);
    const fileId = this.generateFileId(userId, fileTypeEnum);
    const partSize = 5 * 1024 * 1024; // 5MB parts

    // Create multipart upload in S3
    const command = new CreateMultipartUploadCommand({
      Bucket: this.configService.get('AWS_S3_BUCKET'),
      Key: this.getS3Key(fileId, fileName),
      ContentType: fileType,
      Metadata: {
        userId,
        private: options.private?.toString() || 'false',
        ...options.tags,
      },
    });

    const response = await this.s3Client.send(command);
    const uploadId = response.UploadId;

    // Generate pre-signed URLs for each part
    const totalParts = Math.ceil(options.maxSize || this.maxFileSize / partSize);
    const urls = [];

    for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
      const url = await getSignedUrl(
        this.s3Client,
        new UploadPartCommand({
          Bucket: this.configService.get('AWS_S3_BUCKET'),
          Key: this.getS3Key(fileId, fileName),
          UploadId: uploadId,
          PartNumber: partNumber,
        }),
        { expiresIn: 3600 },
      );
      urls.push(url);
    }

    // Save upload record
    await this.saveUploadRecord({
      uploadId,
      fileId,
      userId,
      fileName,
      fileType: fileTypeEnum,
      partSize,
      totalParts,
      status: FileStatus.UPLOADING,
      options,
    });

    return {
      uploadId,
      fileId,
      partSize,
      urls,
    };
  }

  async completeMultipartUpload(
    uploadId: string,
    fileId: string,
    parts: Array<{ ETag: string; PartNumber: number }>,
  ): Promise<any> {
    const uploadRecord = await this.getUploadRecord(uploadId);
    if (!uploadRecord) {
      throw new NotFoundException('Upload not found');
    }

    // Complete multipart upload in S3
    const command = new CompleteMultipartUploadCommand({
      Bucket: this.configService.get('AWS_S3_BUCKET'),
      Key: this.getS3Key(fileId, uploadRecord.fileName),
      UploadId: uploadId,
      MultipartUpload: { Parts: parts },
    });

    await this.s3Client.send(command);

    // Update file record
    const url = `https://${this.configService.get('AWS_S3_BUCKET')}.s3.amazonaws.com/${this.getS3Key(fileId, uploadRecord.fileName)}`;
    
    await this.updateFileRecord(fileId, {
      url,
      status: FileStatus.READY,
    });

    // Clean up upload record
    await this.deleteUploadRecord(uploadId);

    return { fileId, url };
  }

  // File processing methods
  private async processFile(
    file: Express.Multer.File,
    fileType: FileType,
    options: UploadOptions,
  ): Promise<Express.Multer.File & { buffer?: Buffer }> {
    const processedFile = { ...file };

    switch (fileType) {
      case FileType.IMAGE:
        if (options.optimizeImage) {
          processedFile.buffer = await this.optimizeImage(file.path, options);
          processedFile.size = processedFile.buffer.length;
        }
        break;

      case FileType.VIDEO:
        if (options.compressVideo) {
          const compressedPath = await this.compressVideo(file.path);
          processedFile.path = compressedPath;
          processedFile.size = fs.statSync(compressedPath).size;
        }
        break;

      case FileType.DOCUMENT:
        if (options.watermark) {
          processedFile.buffer = await this.addWatermarkToPdf(file.path);
          processedFile.size = processedFile.buffer.length;
        }
        break;
    }

    return processedFile;
  }

  private async optimizeImage(
    filePath: string,
    options: UploadOptions,
  ): Promise<Buffer> {
    let sharpInstance = sharp(filePath);

    // Resize if needed
    if (options.maxSize) {
      sharpInstance = sharpInstance.resize(2000, 2000, {
        fit: 'inside',
        withoutEnlargement: true,
      });
    }

    // Convert to WebP for better compression
    sharpInstance = sharpInstance.webp({
      quality: 80,
      effort: 6,
    });

    // Strip metadata
    sharpInstance = sharpInstance.withMetadata({
      exif: {},
      iptc: {},
      xmp: {},
      tiff: {},
    });

    return sharpInstance.toBuffer();
  }

  private async generateThumbnail(
    file: Express.Multer.File & { buffer?: Buffer },
    fileId: string,
  ): Promise<string> {
    const thumbnailBuffer = await sharp(file.buffer || file.path)
      .resize(300, 300, {
        fit: 'cover',
        position: 'center',
      })
      .jpeg({ quality: 70 })
      .toBuffer();

    const thumbnailName = `${fileId}_thumbnail.jpg`;
    const thumbnailKey = `thumbnails/${thumbnailName}`;

    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.configService.get('AWS_S3_BUCKET'),
        Key: thumbnailKey,
        Body: thumbnailBuffer,
        ContentType: 'image/jpeg',
        ACL: 'public-read',
      }),
    );

    return `https://${this.configService.get('AWS_S3_BUCKET')}.s3.amazonaws.com/${thumbnailKey}`;
  }

  private async compressVideo(filePath: string): Promise<string> {
    const outputPath = path.join(
      this.uploadDir,
      `compressed_${Date.now()}_${path.basename(filePath)}`,
    );

    return new Promise((resolve, reject) => {
      ffmpeg(filePath)
        .videoCodec('libx264')
        .audioCodec('aac')
        .outputOptions([
          '-crf 23',
          '-preset fast',
          '-movflags +faststart',
        ])
        .on('end', () => resolve(outputPath))
        .on('error', reject)
        .save(outputPath);
    });
  }

  // Storage methods
  private async uploadToStorage(
    file: Express.Multer.File & { buffer?: Buffer },
    fileId: string,
    options: UploadOptions,
  ): Promise<{ fileName: string; url: string }> {
    const fileName = `${fileId}${path.extname(file.originalname)}`;
    const fileKey = this.getFileKey(fileId, fileName, options.private);

    // Upload to S3
    if (this.configService.get('STORAGE_TYPE') === 's3') {
      const fileBody = file.buffer || fs.createReadStream(file.path);
      
      await this.s3Client.send(
        new PutObjectCommand({
          Bucket: this.configService.get('AWS_S3_BUCKET'),
          Key: fileKey,
          Body: fileBody,
          ContentType: file.mimetype,
          ContentLength: file.size,
          ACL: options.private ? 'private' : 'public-read',
          Metadata: {
            originalName: file.originalname,
            userId: options.private ? 'private' : undefined,
            ...options.tags,
          },
        }),
      );

      const url = options.private
        ? await this.generatePresignedUrl(fileKey)
        : `https://${this.configService.get('AWS_S3_BUCKET')}.s3.amazonaws.com/${fileKey}`;

      return { fileName, url };
    } else {
      // Local storage
      const localPath = path.join(this.uploadDir, fileKey);
      const dir = path.dirname(localPath);

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      if (file.buffer) {
        fs.writeFileSync(localPath, file.buffer);
      } else {
        fs.copyFileSync(file.path, localPath);
      }

      const url = `/uploads/${fileKey}`;
      return { fileName, url };
    }
  }

  // File validation
  private async validateFile(
    file: Express.Multer.File,
    allowedTypes?: string[],
    maxSize?: number,
  ): Promise<void> {
    // Check file size
    const fileSize = maxSize || this.maxFileSize;
    if (file.size > fileSize) {
      throw new BadRequestException(
        `File size exceeds limit of ${fileSize / 1024 / 1024}MB`,
      );
    }

    // Check file type
    const allowedMimeTypes = allowedTypes || Object.values(this.allowedMimeTypes).flat();
    if (!allowedMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException(
        `File type ${file.mimetype} is not allowed`,
      );
    }

    // Check for malicious files
    await this.scanForMalware(file.path);

    // Validate image dimensions if it's an image
    if (file.mimetype.startsWith('image/')) {
      await this.validateImageDimensions(file.path);
    }
  }

  private async validateImageDimensions(filePath: string): Promise<void> {
    const metadata = await sharp(filePath).metadata();
    
    if (metadata.width > 10000 || metadata.height > 10000) {
      throw new BadRequestException('Image dimensions too large');
    }

    if (metadata.width < 10 || metadata.height < 10) {
      throw new BadRequestException('Image dimensions too small');
    }
  }

  private async scanForMalware(filePath: string): Promise<void> {
    // Integrate with ClamAV or similar antivirus
    // This is a placeholder implementation
    const maliciousPatterns = [
      /eval\(/i,
      /base64_decode/i,
      /system\(/i,
      /shell_exec\(/i,
    ];

    const content = fs.readFileSync(filePath, 'utf8');
    for (const pattern of maliciousPatterns) {
      if (pattern.test(content)) {
        throw new BadRequestException('File contains suspicious content');
      }
    }
  }

  // Utility methods
  private getFileType(mimeType: string): FileType {
    if (mimeType.startsWith('image/')) return FileType.IMAGE;
    if (mimeType.startsWith('video/')) return FileType.VIDEO;
    if (mimeType.startsWith('audio/')) return FileType.AUDIO;
    if (
      mimeType.startsWith('application/pdf') ||
      mimeType.includes('document') ||
      mimeType.includes('text/')
    ) {
      return FileType.DOCUMENT;
    }
    if (
      mimeType.includes('zip') ||
      mimeType.includes('rar') ||
      mimeType.includes('tar') ||
      mimeType.includes('gzip')
    ) {
      return FileType.ARCHIVE;
    }
    return FileType.OTHER;
  }

  private canGenerateThumbnail(fileType: FileType): boolean {
    return [FileType.IMAGE, FileType.VIDEO].includes(fileType);
  }

  private generateFileId(userId: string, fileType: FileType): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    return `${fileType}_${userId}_${timestamp}_${random}`;
  }

  private getFileKey(fileId: string, fileName: string, isPrivate?: boolean): string {
    const prefix = isPrivate ? 'private/' : 'public/';
    const date = new Date();
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    
    return `${prefix}${year}/${month}/${day}/${fileId}/${fileName}`;
  }

  private getS3Key(fileId: string, fileName: string): string {
    return this.getFileKey(fileId, fileName, false);
  }

  private async generateFileHash(filePath: string): Promise<string> {
    const hash = createHash('sha256');
    const stream = fs.createReadStream(filePath);

    return new Promise((resolve, reject) => {
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  private async generatePresignedUrl(key: string, expiresIn = 3600): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.configService.get('AWS_S3_BUCKET'),
      Key: key,
    });

    return getSignedUrl(this.s3Client, command, { expiresIn });
  }

  private async extractMetadata(
    file: Express.Multer.File & { buffer?: Buffer },
    originalFile: Express.Multer.File,
  ): Promise<FileMetadata> {
    const metadata: FileMetadata = {
      originalName: originalFile.originalname,
      mimeType: originalFile.mimetype,
      size: originalFile.size,
      hash: await this.generateFileHash(originalFile.path),
    };

    if (originalFile.mimetype.startsWith('image/')) {
      const imageMetadata = await sharp(originalFile.path).metadata();
      metadata.width = imageMetadata.width;
      metadata.height = imageMetadata.height;
    }

    if (originalFile.mimetype.startsWith('video/')) {
      // Extract video duration using ffprobe
      const duration = await this.getVideoDuration(originalFile.path);
      if (duration) {
        metadata.duration = duration;
      }
    }

    return metadata;
  }

  private async getVideoDuration(filePath: string): Promise<number | undefined> {
    return new Promise((resolve) => {
      ffmpeg.ffprobe(filePath, (err, metadata) => {
        if (err) resolve(undefined);
        resolve(metadata.format.duration);
      });
    });
  }

  // Database operations (placeholder - implement with your ORM)
  private async saveFileRecord(data: any): Promise<any> {
    // Implement with TypeORM/Mongoose
    return data;
  }

  private async findDuplicateFile(hash: string, userId: string): Promise<any> {
    // Implement duplicate detection
    return null;
  }

  private async saveUploadRecord(data: any): Promise<any> {
    // Implement upload tracking
    return data;
  }

  private async getUploadRecord(uploadId: string): Promise<any> {
    // Implement upload record retrieval
    return null;
  }

  private async updateFileRecord(fileId: string, updates: any): Promise<any> {
    // Implement file record update
    return null;
  }

  private async deleteUploadRecord(uploadId: string): Promise<void> {
    // Implement upload record deletion
  }

  private createStorageEngine(): any {
    // Custom storage engine for Multer
    return {
      _handleFile: (req, file, callback) => {
        // Implement custom storage logic
      },
      _removeFile: (req, file, callback) => {
        // Implement file removal logic
      },
    };
  }

  private async cleanupLocalFile(filePath: string): Promise<void> {
    if (fs.existsSync(filePath)) {
      try {
        await promisify(fs.unlink)(filePath);
      } catch (error) {
        console.error('Failed to cleanup local file:', error);
      }
    }
  }

  // Public API methods
  async getFile(fileId: string, userId?: string): Promise<any> {
    // Implement file retrieval with access control
  }

  async deleteFile(fileId: string, userId: string): Promise<void> {
    // Implement file deletion with cleanup
  }

  async listFiles(userId: string, filters?: any): Promise<any[]> {
    // Implement file listing with pagination
  }

  async updateFileMetadata(fileId: string, updates: any, userId: string): Promise<any> {
    // Implement metadata updates
  }

  async generateDownloadUrl(fileId: string, userId?: string): Promise<string> {
    // Implement secure download URL generation
  }
}
```

#### **File Upload Controller with Validation**

```typescript
// src/file-upload/file-upload.controller.ts
import {
  Controller,
  Post,
  Get,
  Delete,
  Put,
  Param,
  Query,
  Body,
  UploadedFile,
  UploadedFiles,
  UseInterceptors,
  UseGuards,
  ParseIntPipe,
  ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor, FilesInterceptor, AnyFilesInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionGuard } from '../rbac/guards/permission.guard';
import { Permission } from '../rbac/decorators/permission.decorator';
import { FileUploadService, FileType } from './file-upload.service';
import {
  UploadFileDto,
  InitiateMultipartUploadDto,
  CompleteMultipartUploadDto,
  UpdateFileMetadataDto,
} from './dto';

@Controller('files')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class FileUploadController {
  constructor(private readonly fileUploadService: FileUploadService) {}

  @Post('upload')
  @Permission('file', 'upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @Body() uploadFileDto: UploadFileDto,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.uploadFile(file, userId, {
      maxSize: uploadFileDto.maxSize,
      allowedTypes: uploadFileDto.allowedTypes,
      generateThumbnail: uploadFileDto.generateThumbnail,
      optimizeImage: uploadFileDto.optimizeImage,
      private: uploadFileDto.private,
      expirationHours: uploadFileDto.expirationHours,
      tags: uploadFileDto.tags,
    });
  }

  @Post('upload/multiple')
  @Permission('file', 'upload')
  @UseInterceptors(FilesInterceptor('files', 10))
  async uploadMultipleFiles(
    @UploadedFiles() files: Express.Multer.File[],
    @Body() uploadFileDto: UploadFileDto,
    @Request() req,
  ) {
    const userId = req.user.userId;
    const results = [];

    for (const file of files) {
      try {
        const result = await this.fileUploadService.uploadFile(file, userId, {
          maxSize: uploadFileDto.maxSize,
          allowedTypes: uploadFileDto.allowedTypes,
          generateThumbnail: uploadFileDto.generateThumbnail,
          optimizeImage: uploadFileDto.optimizeImage,
          private: uploadFileDto.private,
          tags: uploadFileDto.tags,
        });
        results.push({ success: true, ...result });
      } catch (error) {
        results.push({
          success: false,
          fileName: file.originalname,
          error: error.message,
        });
      }
    }

    return {
      total: files.length,
      successful: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
      results,
    };
  }

  @Post('upload/large/initiate')
  @Permission('file', 'upload')
  async initiateMultipartUpload(
    @Body() initiateDto: InitiateMultipartUploadDto,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.initiateMultipartUpload(
      initiateDto.fileName,
      initiateDto.fileType,
      userId,
      {
        maxSize: initiateDto.maxSize,
        private: initiateDto.private,
        tags: initiateDto.tags,
      },
    );
  }

  @Post('upload/large/complete/:uploadId')
  @Permission('file', 'upload')
  async completeMultipartUpload(
    @Param('uploadId') uploadId: string,
    @Body() completeDto: CompleteMultipartUploadDto,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.completeMultipartUpload(
      uploadId,
      completeDto.fileId,
      completeDto.parts,
    );
  }

  @Get()
  @Permission('file', 'read')
  async listFiles(
    @Query('page', ParseIntPipe) page: number = 1,
    @Query('limit', ParseIntPipe) limit: number = 20,
    @Query('type') type?: FileType,
    @Query('search') search?: string,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.listFiles(userId, {
      page,
      limit,
      type,
      search,
    });
  }

  @Get(':id')
  @Permission('file', 'read')
  async getFile(
    @Param('id', ParseUUIDPipe) id: string,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.getFile(id, userId);
  }

  @Get(':id/download')
  @Permission('file', 'download')
  async downloadFile(
    @Param('id', ParseUUIDPipe) id: string,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    const downloadUrl = await this.fileUploadService.generateDownloadUrl(
      id,
      userId,
    );

    return { downloadUrl };
  }

  @Put(':id/metadata')
  @Permission('file', 'update')
  async updateFileMetadata(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateDto: UpdateFileMetadataDto,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    return this.fileUploadService.updateFileMetadata(id, updateDto, userId);
  }

  @Delete(':id')
  @Permission('file', 'delete')
  async deleteFile(
    @Param('id', ParseUUIDPipe) id: string,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    await this.fileUploadService.deleteFile(id, userId);
    
    return { message: 'File deleted successfully' };
  }

  // Image processing endpoints
  @Post(':id/process')
  @Permission('file', 'update')
  async processImage(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() processOptions: any,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    // Implement image processing (resize, crop, filter, etc.)
    return { message: 'Image processing queued' };
  }

  // File conversion endpoints
  @Post(':id/convert')
  @Permission('file', 'update')
  async convertFile(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('targetFormat') targetFormat: string,
    @Request() req,
  ) {
    const userId = req.user.userId;
    
    // Implement file format conversion
    return { message: 'File conversion queued' };
  }

  // Statistics
  @Get('stats/usage')
  @Permission('file', 'read')
  async getUsageStats(@Request() req) {
    const userId = req.user.userId;
    
    // Implement usage statistics
    return {
      totalFiles: 0,
      totalSize: 0,
      byType: {},
      last30Days: [],
    };
  }
}
```

#### **File Validation Pipes**

```typescript
// src/file-upload/pipes/file-validation.pipe.ts
import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { FileTypeValidator as NestFileTypeValidator } from '@nestjs/common';

@Injectable()
export class FileSizeValidationPipe implements PipeTransform {
  constructor(private readonly maxSize: number) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (metadata.type !== 'body' || !value) {
      return value;
    }

    const file = value.file || value;
    if (file && file.size > this.maxSize) {
      throw new BadRequestException(
        `File size exceeds limit of ${this.maxSize / 1024 / 1024}MB`,
      );
    }

    return value;
  }
}

@Injectable()
export class FileTypeValidationPipe implements PipeTransform {
  constructor(private readonly allowedTypes: string[]) {}

  transform(value: any, metadata: ArgumentMetadata) {
    if (metadata.type !== 'body' || !value) {
      return value;
    }

    const file = value.file || value;
    if (file && !this.allowedTypes.includes(file.mimetype)) {
      throw new BadRequestException(
        `File type ${file.mimetype} is not allowed. Allowed types: ${this.allowedTypes.join(', ')}`,
      );
    }

    return value;
  }
}

@Injectable()
export class ImageDimensionsValidationPipe implements PipeTransform {
  constructor(
    private readonly minWidth?: number,
    private readonly maxWidth?: number,
    private readonly minHeight?: number,
    private readonly maxHeight?: number,
  ) {}

  async transform(value: any, metadata: ArgumentMetadata) {
    if (metadata.type !== 'body' || !value) {
      return value;
    }

    const file = value.file || value;
    if (file && file.mimetype.startsWith('image/')) {
      const sharp = require('sharp');
      const metadata = await sharp(file.buffer).metadata();

      if (this.minWidth && metadata.width < this.minWidth) {
        throw new BadRequestException(
          `Image width must be at least ${this.minWidth}px`,
        );
      }

      if (this.maxWidth && metadata.width > this.maxWidth) {
        throw new BadRequestException(
          `Image width must not exceed ${this.maxWidth}px`,
        );
      }

      if (this.minHeight && metadata.height < this.minHeight) {
        throw new BadRequestException(
          `Image height must be at least ${this.minHeight}px`,
        );
      }

      if (this.maxHeight && metadata.height > this.maxHeight) {
        throw new BadRequestException(
          `Image height must not exceed ${this.maxHeight}px`,
        );
      }
    }

    return value;
  }
}
```

### 🎯 Real-World Scenario: Video Streaming Platform
*You're building a video streaming platform like YouTube. Users can upload videos up to 4GB, which need to be processed (transcoded into multiple resolutions), stored efficiently, and delivered via CDN with adaptive bitrate streaming.*

**Interview Questions:**
1. How would you design the file upload system for 4GB videos?
2. What strategies would you implement for video transcoding at scale?
3. How do you handle partial upload failures and resume functionality?
4. What CDN strategy would you use for global video delivery?
5. How do you implement DRM (Digital Rights Management) for premium content?

**Technical Questions:**
1. What are the challenges of multipart uploads and how do you handle them?
2. How do you implement video transcoding pipelines with FFmpeg?
3. What are the best practices for storing large files in the cloud?
4. How do you handle metadata extraction from different file types?

---

**Note**: Due to the character limit, I've provided comprehensive implementations for the first 4 topics. Each topic is extensive and deserves its own detailed guide. The remaining topics (5-12) would follow similar patterns with:

- **Real-time Chat**: WebSocket implementation with Redis Pub/Sub, room management, message persistence, typing indicators, read receipts
- **Online/Offline Status**: WebSocket heartbeats, Redis presence tracking, last seen timestamps
- **Payment Gateway**: Stripe/Razorpay integration with webhooks, payment intent management, subscription handling
- **Email Service**: Nodemailer with templates, queue management, delivery tracking, unsubscribe handling
- **Refresh Token Rotation**: JWT refresh token rotation with Redis blacklisting, automatic token refresh
- **Background Jobs**: BullMQ/Redis queues with priority jobs, retry logic, job monitoring
- **Cloud Storage**: Multi-cloud storage abstraction (S3, GCS, Azure), CDN integration, file lifecycle management
- **Multi-tenant**: Database per tenant vs schema per tenant, tenant isolation, cross-tenant operations

Each implementation would include:
1. Complete TypeScript service with best practices
2. Database models/schemas
3. API controllers with validation
4. Security considerations
5. Performance optimizations
6. Real-world scenario questions
7. Interview questions for senior developers

