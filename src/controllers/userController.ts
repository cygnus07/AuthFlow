import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { emailService } from '../services/emailService';
import User from '../models/userModel';
import { config } from '../config/environment';
import { AppError, asyncHandler } from '../middleware/errorHandler';
import { sendSuccess, sendError, ErrorCodes } from '../utils/responseHelper';
import { logger } from '../utils/logger';
import BlacklistedToken from '../models/blacklistedTokenModel';
import { AuthenticatedRequest } from '../types/userTypes';
import { UserRole, AccountStatus } from '../types/userTypes';

import {
  RegisterInput,
  LoginInput,
  RefreshTokenInput,
  UpdateProfileInput,
  ChangePasswordInput,
  AdminUpdateUserInput
} from '../validators/userValidator';

// Helper function to generate OTP
const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Helper function to generate JWT tokens
const generateTokens = (userId: string): { token: string; refreshToken: string } => {
  if (!config.JWT_SECRET || !config.JWT_REFRESH_SECRET) {
    logger.error('JWT secrets are not defined in config');
    throw new AppError('Internal server configuration error', 500);
  }

  const jwtSecret = config.JWT_SECRET as string;
  const refreshSecret = config.JWT_REFRESH_SECRET as string;

  try {
    const token = jwt.sign(
      { userId },
      jwtSecret,
      { expiresIn: config.JWT_EXPIRES_IN as string }
    );

    const refreshToken = jwt.sign(
      { userId },
      refreshSecret,
      { expiresIn: config.JWT_REFRESH_EXPIRES_IN as string }
    );

    logger.debug('Tokens generated successfully', { userId });
    return { token, refreshToken };
  } catch (error) {
    logger.error('Failed to generate tokens', { userId, error });
    throw new AppError('Failed to generate authentication tokens', 500);
  }
};

// Helper function to create user response (removes sensitive fields)
const createUserResponse = (user: any) => {
  const userObj = user.toObject ? user.toObject() : user;
  const { 
    password, 
    refreshToken, 
    passwordResetToken, 
    emailVerificationToken, 
    passwordResetExpires,
    ...safeUser 
  } = userObj;
  return safeUser;
};

// Helper function to validate password strength
const validatePasswordStrength = (password: string): { isValid: boolean; message?: string } => {
  if (password.length < 8) {
    return { isValid: false, message: 'Password must be at least 8 characters long' };
  }
  
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
    return { 
      isValid: false, 
      message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number' 
    };
  }
  
  return { isValid: true };
};

export const userController = {
  // Register new user
  register: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const { firstName, lastName, username, email, password, role } = req.body as RegisterInput;
    
    logger.info('User registration attempt', { email, username, userAgent: req.get('User-Agent'), ip: req.ip });

    try {
      // Validate password strength
      const passwordValidation = validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        logger.auth('registration_failed', undefined, email, false, new Error(passwordValidation.message));
        return sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
      }

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [
          { email },
          ...(username ? [{ username }] : [])
        ]
      });

      if (existingUser) {
        const conflictField = existingUser.email === email ? 'email' : 'username';
        const conflictMessage = existingUser.email === email 
          ? (existingUser.emailVerified 
            ? 'Email already in use' 
            : 'Email already registered but not verified. Check your email for verification code.')
          : 'Username already taken';
        
        logger.auth('registration_failed', undefined, email, false, new Error(`${conflictField} conflict`));
        logger.security('duplicate_registration_attempt', req.ip, req.get('User-Agent'), { email, username, conflictField });
        
        return sendError(res, conflictMessage, ErrorCodes.CONFLICT, 'DUPLICATE_FIELD');
      }

      // Generate OTP for email verification
      const otp = generateOTP();
      const emailVerificationToken = crypto
        .createHash('sha256')
        .update(otp)
        .digest('hex');

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Create new user
      const user = new User({
        firstName,
        lastName,
        username,
        email,
        password: hashedPassword,
        role: role || UserRole.USER,
        emailVerified: false,
        emailVerificationToken,
        passwordResetExpires: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        status: AccountStatus.PENDING
      });

      await user.save();
      logger.database('create', 'users', true, Date.now() - startTime);

      // Send verification email
      try {
        await emailService.sendVerificationEmail(email, firstName || username || 'User', otp);
        logger.email('verification_email_sent', email, true);
      } catch (emailError) {
        logger.email('verification_email_failed', email, false, undefined, emailError);
        // Don't fail registration if email fails, but log the error
        logger.error('Failed to send verification email during registration', { 
          email, 
          error: emailError instanceof Error ? emailError.message : String(emailError) 
        });
      }

      logger.auth('registration_success', user._id.toString(), email);
      logger.performance('user_registration', Date.now() - startTime, { email, userId: user._id });

      sendSuccess(res, {
        user: createUserResponse(user)
      }, 'Registration successful. Please check your email for verification instructions.', 201);

    } catch (error) {
      logger.database('create', 'users', false, Date.now() - startTime, error);
      logger.auth('registration_failed', undefined, email, false, error);
      throw error;
    }
  }),

  // Verify email
  verifyEmail: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const { email, otp } = req.body;

    if (!email || !otp) {
      logger.auth('email_verification_failed', undefined, email, false, new Error('Missing email or OTP'));
      return sendError(res, 'Email and OTP are required', ErrorCodes.BAD_REQUEST, 'MISSING_FIELDS');
    }

    logger.info('Email verification attempt', { email, ip: req.ip });

    try {
      // Hash the OTP for comparison
      const hashedOTP = crypto
        .createHash('sha256')
        .update(otp)
        .digest('hex');

      // Find and update user
      const user = await User.findOneAndUpdate(
        {
          email,
          emailVerificationToken: hashedOTP,
          passwordResetExpires: { $gt: new Date() },
          emailVerified: false
        },
        {
          $set: {
            emailVerified: true,
            status: AccountStatus.ACTIVE
          },
          $unset: {
            emailVerificationToken: 1,
            passwordResetExpires: 1
          }
        },
        { new: true }
      );

      if (!user) {
        logger.auth('email_verification_failed', undefined, email, false, new Error('Invalid or expired code'));
        logger.security('invalid_verification_attempt', req.ip, req.get('User-Agent'), { email, otp: otp.substring(0, 2) + '****' });
        return sendError(res, 'Invalid, expired, or already verified code', ErrorCodes.BAD_REQUEST, 'INVALID_VERIFICATION_CODE');
      }

      // Generate tokens
      const { token, refreshToken } = generateTokens(user._id.toString());

      // Send welcome email
      try {
        await emailService.sendWelcomeEmail(user.email, user.firstName || user.username || 'User');
        logger.email('welcome_email_sent', user.email, true);
      } catch (emailError) {
        logger.email('welcome_email_failed', user.email, false, undefined, emailError);
        // Don't fail verification if welcome email fails
      }

      logger.auth('email_verification_success', user._id.toString(), email);
      logger.performance('email_verification', Date.now() - startTime, { email, userId: user._id });

      sendSuccess(res, {
        user: createUserResponse(user),
        token,
        refreshToken
      }, 'Email verified successfully');

    } catch (error) {
      logger.auth('email_verification_failed', undefined, email, false, error);
      logger.performance('email_verification_failed', Date.now() - startTime, { email, error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }),

  // Resend verification email
  resendVerificationEmail: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
      return sendError(res, 'Email is required', ErrorCodes.BAD_REQUEST, 'MISSING_EMAIL');
    }

    logger.info('Resend verification email request', { email, ip: req.ip });

    const user = await User.findOne({ email, emailVerified: false });
    if (!user) {
      logger.security('resend_verification_invalid_email', req.ip, req.get('User-Agent'), { email });
      return sendError(res, 'User not found or already verified', ErrorCodes.BAD_REQUEST, 'USER_NOT_FOUND_OR_VERIFIED');
    }

    // Generate new OTP
    const otp = generateOTP();
    const emailVerificationToken = crypto
      .createHash('sha256')
      .update(otp)
      .digest('hex');

    // Update user with new verification token
    user.emailVerificationToken = emailVerificationToken;
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    // Send verification email
    try {
      await emailService.sendVerificationEmail(email, user.firstName || user.username || 'User', otp);
      logger.email('resend_verification_email_sent', email, true);
      logger.auth('resend_verification_success', user._id.toString(), email);
      
      sendSuccess(res, undefined, 'Verification email sent successfully');
    } catch (emailError) {
      logger.email('resend_verification_email_failed', email, false, undefined, emailError);
      throw new AppError('Failed to send verification email', 500);
    }
  }),

  // Login user
  login: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const { email, password } = req.body as LoginInput;

    logger.info('User login attempt', { email, ip: req.ip, userAgent: req.get('User-Agent') });

    try {
      // Find user and include password for comparison
      const user = await User.findOne({ email }).select('+password');
      if (!user) {
        logger.auth('login_failed', undefined, email, false, new Error('User not found'));
        logger.security('login_attempt_nonexistent_user', req.ip, req.get('User-Agent'), { email });
        return sendError(res, 'Invalid credentials', ErrorCodes.UNAUTHORIZED, 'INVALID_CREDENTIALS');
      }

      // Check if account is active
      if (user.status !== AccountStatus.ACTIVE) {
        logger.auth('login_failed', user._id.toString(), email, false, new Error(`Account status: ${user.status}`));
        logger.security('login_attempt_inactive_account', req.ip, req.get('User-Agent'), { 
          email, 
          userId: user._id.toString(),
          status: user.status 
        });
        return sendError(res, 'Account is suspended or inactive', ErrorCodes.FORBIDDEN, 'ACCOUNT_INACTIVE');
      }

      if (!user.password) {
        logger.error('Password not set for user', { userId: user._id.toString(), email });
        throw new AppError('Account configuration error', 500);
      }

      // Check password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        logger.auth('login_failed', user._id.toString(), email, false, new Error('Invalid password'));
        logger.security('login_failed_invalid_password', req.ip, req.get('User-Agent'), { 
          email, 
          userId: user._id.toString() 
        });
        return sendError(res, 'Invalid credentials', ErrorCodes.UNAUTHORIZED, 'INVALID_CREDENTIALS');
      }

      // Check if email is verified
      if (!user.emailVerified) {
        logger.auth('login_failed', user._id.toString(), email, false, new Error('Email not verified'));
        return sendError(res, 'Email not verified. Please check your email for verification instructions.', ErrorCodes.FORBIDDEN, 'EMAIL_NOT_VERIFIED');
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Generate tokens
      const { token, refreshToken } = generateTokens(user._id.toString());

      logger.auth('login_success', user._id.toString(), email);
      logger.performance('user_login', Date.now() - startTime, { email, userId: user._id });

      sendSuccess(res, {
        user: createUserResponse(user),
        token,
        refreshToken
      }, 'Login successful');

    } catch (error) {
      logger.auth('login_failed', undefined, email, false, error);
      logger.performance('user_login_failed', Date.now() - startTime, { email, error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }),

  // Refresh token
  refreshToken: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body as RefreshTokenInput;

    if (!refreshToken) {
      return sendError(res, 'Refresh token is required', ErrorCodes.BAD_REQUEST, 'MISSING_REFRESH_TOKEN');
    }

    logger.info('Token refresh attempt', { ip: req.ip });

    try {
      // Check if token is blacklisted
      const blacklistedToken = await BlacklistedToken.findOne({ token: refreshToken });
      if (blacklistedToken) {
        logger.security('blacklisted_token_usage_attempt', req.ip, req.get('User-Agent'), { token: refreshToken.substring(0, 20) + '...' });
        return sendError(res, 'Token has been revoked', ErrorCodes.UNAUTHORIZED, 'TOKEN_REVOKED');
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET as string) as { userId: string };

      if (!config.JWT_SECRET) {
        logger.error('JWT_SECRET is not defined in config');
        throw new AppError('Internal server configuration error', 500);
      }

      // Generate new access token
      const token = jwt.sign(
        { userId: decoded.userId },
        config.JWT_SECRET as string,
        { expiresIn: config.JWT_EXPIRES_IN as string }
      );

      logger.auth('token_refresh_success', decoded.userId);

      sendSuccess(res, { token }, 'Token refreshed successfully');

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        logger.security('invalid_refresh_token', req.ip, req.get('User-Agent'), { error: error.message });
        return sendError(res, 'Invalid refresh token', ErrorCodes.UNAUTHORIZED, 'INVALID_REFRESH_TOKEN');
      }
      
      logger.auth('token_refresh_failed', undefined, undefined, false, error);
      throw error;
    }
  }),

  // Forgot password
  forgotPassword: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
      return sendError(res, 'Email is required', ErrorCodes.BAD_REQUEST, 'MISSING_EMAIL');
    }

    logger.info('Password reset request', { email, ip: req.ip });

    const user = await User.findOne({ email });

    // Always return success message for security (don't reveal if user exists)
    const successMessage = 'If a user with that email exists, a password reset link has been sent';

    if (!user) {
      logger.security('password_reset_nonexistent_user', req.ip, req.get('User-Agent'), { email });
      return sendSuccess(res, undefined, successMessage);
    }

    try {
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');

      // Save reset token
      user.passwordResetToken = hashedToken;
      user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await user.save();

      // Send reset email
      await emailService.sendPasswordResetEmail(
        user.email,
        user.firstName || user.username || 'User',
        resetToken
      );

      logger.auth('password_reset_request_success', user._id.toString(), email);
      logger.email('password_reset_email_sent', email, true);

      sendSuccess(res, undefined, 'Password reset link sent to your email. The link is valid for 1 hour.');

    } catch (emailError) {
      // Clean up reset token if email fails
      user.passwordResetToken = undefined as any;
      user.passwordResetExpires = undefined as any;
      await user.save();
      
      logger.email('password_reset_email_failed', email, false, undefined, emailError);
      logger.auth('password_reset_request_failed', user._id.toString(), email, false, emailError);
      
      throw new AppError('Failed to send password reset email', 500);
    }
  }),

  // Reset password
  resetPassword: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { token, password, confirmPassword } = req.body;

    if (!token || !password || !confirmPassword) {
      return sendError(res, 'Token, password and confirm password are required', ErrorCodes.BAD_REQUEST, 'MISSING_FIELDS');
    }

    if (password !== confirmPassword) {
      return sendError(res, 'Passwords do not match', ErrorCodes.BAD_REQUEST, 'PASSWORD_MISMATCH');
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
      return sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
    }

    logger.info('Password reset attempt', { ip: req.ip });

    try {
      // Hash token for comparison
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

      // Find user with valid reset token
      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: new Date() }
      });

      if (!user) {
        logger.security('invalid_password_reset_token', req.ip, req.get('User-Agent'), { token: token.substring(0, 10) + '...' });
        return sendError(res, 'Password reset token is invalid or has expired', ErrorCodes.BAD_REQUEST, 'INVALID_RESET_TOKEN');
      }

      // Update password
      user.password = await bcrypt.hash(password, 12);
      user.passwordResetToken = undefined as any;
      user.passwordResetExpires = undefined as any;
      user.passwordChangedAt = new Date();
      await user.save();

      // Send confirmation email
      try {
        await emailService.sendPasswordChangeNotification(
          user.email,
          user.firstName || user.username || 'User'
        );
        logger.email('password_change_notification_sent', user.email, true);
      } catch (emailError) {
        logger.email('password_change_notification_failed', user.email, false, undefined, emailError);
        // Don't fail password reset if notification email fails
      }

      logger.auth('password_reset_success', user._id.toString(), user.email);

      sendSuccess(res, undefined, 'Your password has been reset successfully. You can now log in with your new password.');

    } catch (error) {
      logger.auth('password_reset_failed', undefined, undefined, false, error);
      throw error;
    }
  }),

  // Get current user profile
  getProfile: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const user = req.user;

    if (!user) {
      logger.error('User not found in authenticated request');
      return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
    }

    logger.info('Profile retrieved', { userId: user._id.toString() });

    sendSuccess(res, {
      user: createUserResponse(user)
    }, 'User profile retrieved successfully');
  }),

  // Update user profile
  updateProfile: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { firstName, lastName, username, email, phone } = req.body as UpdateProfileInput;
    
    if (!req.user) {
      return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
    }
    
    const userId = req.user._id;
    logger.info('Profile update attempt', { userId: userId.toString(), email, username });

    // Check if email or username is being changed and already exists
    const updateData: any = {};
    
    if (email && email !== req.user.email) {
      const existingUser = await User.findOne({ email, _id: { $ne: userId } });
      if (existingUser) {
        logger.security('profile_update_duplicate_email', req.ip, req.get('User-Agent'), { 
          userId: userId.toString(), 
          attemptedEmail: email 
        });
        return sendError(res, 'Email already in use', ErrorCodes.CONFLICT, 'EMAIL_IN_USE');
      }
      updateData.email = email;
      updateData.emailVerified = false; // Require re-verification if email changes
    }

    if (username && username !== req.user.username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        logger.security('profile_update_duplicate_username', req.ip, req.get('User-Agent'), { 
          userId: userId.toString(), 
          attemptedUsername: username 
        });
        return sendError(res, 'Username already taken', ErrorCodes.CONFLICT, 'USERNAME_TAKEN');
      }
      updateData.username = username;
    }

    // Add other fields
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (phone !== undefined) updateData.phone = phone;

    try {
      // Update user
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        updateData,
        { new: true, runValidators: true }
      );

      if (!updatedUser) {
        return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      }

      logger.auth('profile_update_success', userId.toString(), updatedUser.email);

      sendSuccess(res, {
        user: createUserResponse(updatedUser)
      }, 'Profile updated successfully');

    } catch (error) {
      logger.auth('profile_update_failed', userId.toString(), req.user.email, false, error);
      throw error;
    }
  }),

  // Change password
  changePassword: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { currentPassword, newPassword } = req.body as ChangePasswordInput;

    if (!req.user) {
      return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
    }
    
    const userId = req.user._id;
    logger.info('Password change attempt', { userId: userId.toString() });

    if (currentPassword === newPassword) {
      return sendError(res, 'New password must be different from current password', ErrorCodes.BAD_REQUEST, 'SAME_PASSWORD');
    }

    // Validate new password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.isValid) {
      return sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
    }

    try {
      // Find user with password
      const user = await User.findById(userId).select('+password');
      if (!user) {
        return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      }

      if (!user.password) {
        logger.error('Password not set for user', { userId: userId.toString() });
        throw new AppError('Account configuration error', 500);
      }

      // Check current password
      const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordValid) {
        logger.auth('password_change_failed', userId.toString(), user.email, false, new Error('Invalid current password'));
        logger.security('password_change_invalid_current', req.ip, req.get('User-Agent'), { userId: userId.toString() });
        return sendError(res, 'Current password is incorrect', ErrorCodes.UNAUTHORIZED, 'INVALID_CURRENT_PASSWORD');
      }

      // Update password
      user.password = await bcrypt.hash(newPassword, 12);
      user.passwordChangedAt = new Date();
      await user.save();

      // Send notification email
      try {
        await emailService.sendPasswordChangeNotification(
          user.email,
          user.firstName || user.username || 'User'
        );
        logger.email('password_change_notification_sent', user.email, true);
      } catch (emailError) {
        logger.email('password_change_notification_failed', user.email, false, undefined, emailError);
        // Don't fail password change if notification email fails
      }

      logger.auth('password_change_success', userId.toString(), user.email);

      sendSuccess(res, undefined, 'Password changed successfully');

    } catch (error) {
      logger.auth('password_change_failed', userId.toString(), req.user.email, false, error);
      throw error;
    }
  }),

  // Admin: Get all users
  getAllUsers: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const startTime = Date.now();
    const page = parseInt(req.query['page'] as string) || 1;
    const limit = Math.min(parseInt(req.query['limit'] as string) || 10, 100); // Cap at 100
    const skip = (page - 1) * limit;

    logger.info('Admin get all users request', { page, limit, ip: req.ip });

    try {
      const [users, total] = await Promise.all([
        User.find()
          .skip(skip)
          .limit(limit)
          .sort({ createdAt: -1 }),
        User.countDocuments()
      ]);

      logger.database('find', 'users', true, Date.now() - startTime);
      logger.performance('get_all_users', Date.now() - startTime, { page, limit, total });

      sendSuccess(res, {
        users: users.map(createUserResponse),
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      }, 'Users retrieved successfully');

    } catch (error) {
      logger.database('find', 'users', false, Date.now() - startTime, error);
      throw error;
    }
  }),

  // Admin: Get user by ID
  getUserById: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];
    logger.info('Admin get user by ID request', { userId, ip: req.ip });

    const user = await User.findById(userId);

    if (!user) {
      logger.info('Admin requested non-existent user', { userId });
      return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
    }

    sendSuccess(res, {
      user: createUserResponse(user)
    }, 'User retrieved successfully');
  }),

  // Admin: Update user
  updateUser: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];
    const { firstName, lastName, username, email, role, status } = req.body as AdminUpdateUserInput;

    logger.info('Admin update user request', { userId, email, username, role, status, adminIp: req.ip });

    // Check if email or username is already in use
    const conflictQuery = [];
    if (email) conflictQuery.push({ email });
    if (username) conflictQuery.push({ username });

    if (conflictQuery.length > 0) {
      const existingUser = await User.findOne({
        $or: conflictQuery,
        _id: { $ne: userId }
      });

      if (existingUser) {
        const field = existingUser.email === email ? 'Email' : 'Username';
        logger.security('admin_update_user_duplicate_field', req.ip, req.get('User-Agent'), { 
          userId, 
          field: field.toLowerCase(), 
          value: field === 'Email' ? email : username 
        });
        return sendError(res, `${field} already in use`, ErrorCodes.CONFLICT, 'DUPLICATE_FIELD');
      }
    }

    try {
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { firstName, lastName, username, email, role, status },
        { new: true, runValidators: true }
      );

      if (!updatedUser) {
        logger.info('Admin attempted to update non-existent user', { userId });
        return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      }

      logger.auth('admin_update_user_success', userId, updatedUser.email);

      sendSuccess(res, {
        user: createUserResponse(updatedUser)
      }, 'User updated successfully');

    } catch (error) {
      logger.auth('admin_update_user_failed', userId, email, false, error);
      throw error;
    }
  }),

  // Admin: Delete user
  deleteUser: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];
    logger.info('Admin delete user request', { userId, adminIp: req.ip });

    try {
      const user = await User.findByIdAndDelete(userId);

      if (!user) {
        logger.info('Admin attempted to delete non-existent user', { userId });
        return sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      }

      logger.auth('admin_delete_user_success', userId, user.email);
      logger.security('user_deleted_by_admin', req.ip, req.get('User-Agent'), { 
        deletedUserId: userId, 
        deletedUserEmail: user.email 
      });

      sendSuccess(res, undefined, 'User deleted successfully');

    } catch (error) {
      logger.auth('admin_delete_user_failed', userId, undefined, false, error);
      throw error;
    }
  }),

  // Logout user
  logout: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return sendError(res, 'Refresh token is required', ErrorCodes.BAD_REQUEST, 'MISSING_REFRESH_TOKEN');
    }

    logger.info('User logout attempt', { ip: req.ip });

    try {
      // Verify token to get expiration
      const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET as string) as { exp: number; userId: string };

      // Add to blacklist
      await BlacklistedToken.create({
        token: refreshToken,
        expiresAt: new Date(decoded.exp * 1000)
      });

      logger.auth('logout_success', decoded.userId);

      sendSuccess(res, undefined, 'Logout successful');

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        logger.security('invalid_logout_token', req.ip, req.get('User-Agent'), { error: error.message });
        return sendError(res, 'Invalid refresh token', ErrorCodes.UNAUTHORIZED, 'INVALID_REFRESH_TOKEN');
      }
      
      logger.auth('logout_failed', undefined, undefined, false, error);
      throw error;
    }
  }),

  // Google Authentication
  googleAuth: passport.authenticate('google', { scope: ['profile', 'email'] }),

  googleCallback: asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const startTime = Date.now();const updatedUser = await User.findByIdAndUpdate(
        userId,
        { firstName,
    
    await new Promise<void>((resolve, reject) => {
      passport.authenticate('google', { session: false }, async (err: Error | null, user: any) => {
        if (err) {
          logger.auth('google_auth_callback_error', undefined, undefined, false, err);
          logger.security('google_auth_error', req.ip, req.get('User-Agent'), { error: err.message });
          res.redirect(`${config.CLIENT_URL}/login?error=${encodeURIComponent('Google authentication failed')}`);
          return reject(err);
        }

        if (!user) {
          logger.auth('google_auth_no_user', undefined, undefined, false, new Error('No user from Google authentication'));
          logger.security('google_auth_no_user', req.ip, req.get('User-Agent'));
          res.redirect(`${config.CLIENT_URL}/login?error=${encodeURIComponent('Could not authenticate with Google')}`);
          return reject(new Error('No user from Google authentication'));
        }

        try {
          const userId = typeof user._id === 'string' ? user._id : user._id.toString();
          const { token, refreshToken } = generateTokens(userId);

          logger.auth('google_auth_success', userId, user.email);
          logger.performance('google_auth_callback', Date.now() - startTime, { userId, email: user.email });

          res.redirect(
            `${config.CLIENT_URL}/social-auth-success?token=${encodeURIComponent(token)}&refreshToken=${encodeURIComponent(refreshToken)}`
          );
          resolve();
        } catch (tokenError) {
          logger.auth('google_auth_token_generation_failed', user._id?.toString(), user.email, false, tokenError);
          logger.error('Failed to generate tokens after Google auth', { 
            userId: user._id?.toString(), 
            email: user.email, 
            error: tokenError instanceof Error ? tokenError.message : String(tokenError) 
          });
          
          res.redirect(`${config.CLIENT_URL}/login?error=${encodeURIComponent('Authentication successful but token generation failed')}`);
          resolve();
        }
      })(req, res, next);
    });
  })
};