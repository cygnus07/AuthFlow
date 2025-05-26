import { z } from 'zod';
import { UserRole, AccountStatus } from '../types/userTypes';

// Common patterns
const emailSchema = z.string().trim().toLowerCase().email('Invalid email address');
const phoneSchema = z.string().trim().min(10, 'Phone number must be at least 10 digits').max(15);
const usernameSchema = z.string()
  .trim()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username cannot exceed 30 characters')
  .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores');

const passwordSchema = z.string()
  .min(8, 'Password must be at least 8 characters')
  .max(100, 'Password cannot exceed 100 characters')
  .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Must contain at least one special character');

// Address schema (optional for universal use)
const addressSchema = z.object({
  fullName: z.string().trim().min(2, 'Full name must be at least 2 characters').optional(),
  addressLine1: z.string().trim().min(5, 'Address must be at least 5 characters').optional(),
  addressLine2: z.string().trim().optional(),
  city: z.string().trim().min(2).optional(),
  state: z.string().trim().min(2).optional(),
  postalCode: z.string().trim().min(5).optional(),
  country: z.string().trim().min(2).optional(),
  phone: phoneSchema.optional(),
  isDefault: z.boolean().optional()
}).partial().refine(data => Object.keys(data).length > 0, {
  message: 'At least one address field must be provided'
});

// Base user schema
const baseUserSchema = z.object({
  firstName: z.string().trim().min(2, 'First name must be at least 2 characters').optional(),
  lastName: z.string().trim().min(2, 'Last name must be at least 2 characters').optional(),
  username: usernameSchema.optional(),
  email: emailSchema,
  phone: phoneSchema.optional(),
  avatar: z.string().trim().url('Invalid avatar URL').or(z.literal('')).optional(),
});

// Auth schemas
export const registerSchema = baseUserSchema.extend({
  password: passwordSchema,
  confirmPassword: z.string().min(1, 'Please confirm your password'),
  role: z.nativeEnum(UserRole).default(UserRole.USER).optional(),
  addresses: z.array(addressSchema).max(5).optional(),
}).refine(data => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required')
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required')
});

// Profile schemas
export const updateProfileSchema = baseUserSchema.extend({
  phone: phoneSchema.optional(),
  preferences: z.record(z.any()).optional(),
}).partial().refine(data => Object.keys(data).length > 0, {
  message: 'At least one field must be provided'
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
  confirmNewPassword: z.string().min(1, 'Please confirm your new password'),
}).refine(data => data.newPassword === data.confirmNewPassword, {
  message: "New passwords don't match",
  path: ["confirmNewPassword"],
}).refine(data => data.currentPassword !== data.newPassword, {
  message: "New password must be different from current password",
  path: ["newPassword"],
});

export const adminUpdateUserSchema = baseUserSchema.extend({
  role: z.nativeEnum(UserRole).optional(),
  status: z.nativeEnum(AccountStatus).optional(),
  emailVerified: z.boolean().optional(),
  addresses: z.array(addressSchema).optional(),
  metadata: z.record(z.any()).optional(),
}).partial();

// Email verification schemas
export const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
  email: emailSchema.optional(), // Optional for cases where token is sufficient
});

export const resendVerificationSchema = z.object({
  email: emailSchema,
});

// Password recovery schemas
export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: passwordSchema,
  confirmNewPassword: z.string().min(1, 'Please confirm your new password'),
}).refine(data => data.newPassword === data.confirmNewPassword, {
  message: "Passwords don't match",
  path: ["confirmNewPassword"],
});

// OAuth schemas
export const oAuthCallbackSchema = z.object({
  code: z.string().min(1, 'Authorization code is required'),
  state: z.string().optional(),
});

// Type exports
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type AdminUpdateUserInput = z.infer<typeof adminUpdateUserSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type OAuthCallbackInput = z.infer<typeof oAuthCallbackSchema>;

// Additional type interfaces for request validation
export interface RegisterRequest {
  firstName?: string;
  lastName?: string;
  username?: string;
  email: string;
  password: string;
  role?: UserRole;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  username?: string;
  email?: string;
  phone?: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface AdminUpdateUserRequest {
  firstName?: string;
  lastName?: string;
  username?: string;
  email?: string;
  role?: UserRole;
  status?: AccountStatus;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}
