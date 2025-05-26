import { Request } from 'express';
import { Types, Document } from 'mongoose';

export enum UserRole {
  USER = 'user',          // Basic user role
  ADMIN = 'admin',        // Full administrative privileges
  EDITOR = 'editor',      // Content management privileges
  MODERATOR = 'moderator',// Community moderation privileges
  CUSTOMER = 'customer',  // For e-commerce applications
  VENDOR = 'vendor',     // For marketplace applications
  // Add other roles as needed
}

export enum AccountStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  DELETED = 'deleted',
  PENDING = 'pending',    // For email verification or approval
  BANNED = 'banned'      // For users who violated terms
}

export interface Address {
  _id?: Types.ObjectId;
  fullName?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  phone?: string;
  isDefault?: boolean;
  [key: string]: any; // For additional address properties
}

export interface UserDocument {
  _id: Types.ObjectId;
  email: string;
  password?: string; // Optional for OAuth users
  username?: string; // Added username field
  firstName?: string;
  lastName?: string;
  role: UserRole;
  status: AccountStatus;
  avatar?: string;
  phone?: string;
  addresses?: Address[]; // Made optional
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  passwordChangedAt?: Date;
  emailVerified: boolean;
  // OAuth providers
  googleId?: string;
  facebookId?: string;
  githubId?: string; // Added GitHub OAuth
  emailVerificationToken?: string;
  lastLogin?: Date;
  refreshToken?: string;
  // Additional fields
  preferences?: Map<string, any> | Record<string, any>;
  metadata?: Map<string, any> | Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  // Virtuals
  fullName?: string;
}

// Basic user identification for auth purposes
export interface AuthUser {
  _id: Types.ObjectId;
  email: string;
  username?: string;
  role: UserRole;
  status?: AccountStatus;
  emailVerified?: boolean;
  [key: string]: any; // For additional properties
}

export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
}

declare module 'express' {
  interface Request {
    user?: AuthUser;
  }
}

// Utility types
export interface UserProfile {
  _id: Types.ObjectId;
  email: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  fullName?: string;
  avatar?: string;
  role: UserRole;
  status: AccountStatus;
  emailVerified: boolean;
  createdAt: Date;
}

export interface UserUpdateData {
  firstName?: string;
  lastName?: string;
  username?: string;
  phone?: string;
  avatar?: string;
  preferences?: Record<string, any>;
}

export interface PasswordResetData {
  token: string;
  newPassword: string;
}


export interface IUser extends Document {
  _id: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  googleId?: string;
  facebookId?: string;
  emailVerified: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
