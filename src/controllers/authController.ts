import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { emailService } from '../services/emailService';
import User from '../models/userModel';
import { config } from '../config/environment';
import { AppError, asyncHandler } from '../middleware/errorHandler';
import { sendSuccess, sendError, ErrorCodes } from '../utils/apiResponse'
import { logger } from '../utils/logger';
import BlacklistedToken from '../models/blacklistedTokenModel';
import { UserRole, AccountStatus } from '../types/userTypes';

import {
  RegisterInput,
  LoginInput,
  RefreshTokenInput,
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

   const tokenOptions: jwt.SignOptions = { 
    expiresIn: config.JWT_EXPIRES_IN as any
  };
  
  const refreshOptions: jwt.SignOptions = { 
    expiresIn: config.JWT_REFRESH_EXPIRES_IN as any
  };

  try {
    const token = jwt.sign(
    { userId },
    jwtSecret,
    tokenOptions
  );

  const refreshToken = jwt.sign(
    { userId },
    refreshSecret,
    refreshOptions
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

export const authController = {
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
        sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
        return
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
        
         sendError(res, conflictMessage, ErrorCodes.CONFLICT, 'DUPLICATE_FIELD');
         return
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
       sendError(res, 'Email and OTP are required', ErrorCodes.BAD_REQUEST, 'MISSING_FIELDS');
      return
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
        sendError(res, 'Invalid, expired, or already verified code', ErrorCodes.BAD_REQUEST, 'INVALID_VERIFICATION_CODE');
        return
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
       sendError(res, 'Email is required', ErrorCodes.BAD_REQUEST, 'MISSING_EMAIL');
      return
    }

    logger.info('Resend verification email request', { email, ip: req.ip });

    const user = await User.findOne({ email, emailVerified: false });
    if (!user) {
      logger.security('resend_verification_invalid_email', req.ip, req.get('User-Agent'), { email });
       sendError(res, 'User not found or already verified', ErrorCodes.BAD_REQUEST, 'USER_NOT_FOUND_OR_VERIFIED');
      return
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
         sendError(res, 'Invalid credentials', ErrorCodes.UNAUTHORIZED, 'INVALID_CREDENTIALS');
        return
      }

      // Check if account is active
      if (user.status !== AccountStatus.ACTIVE) {
        logger.auth('login_failed', user._id.toString(), email, false, new Error(`Account status: ${user.status}`));
        logger.security('login_attempt_inactive_account', req.ip, req.get('User-Agent'), { 
          email, 
          userId: user._id.toString(),
          status: user.status 
        });
         sendError(res, 'Account is suspended or inactive', ErrorCodes.FORBIDDEN, 'ACCOUNT_INACTIVE');
        return
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
         sendError(res, 'Invalid credentials', ErrorCodes.UNAUTHORIZED, 'INVALID_CREDENTIALS');
         return
      }

      // Check if email is verified
      if (!user.emailVerified) {
        logger.auth('login_failed', user._id.toString(), email, false, new Error('Email not verified'));
         sendError(res, 'Email not verified. Please check your email for verification instructions.', ErrorCodes.FORBIDDEN, 'EMAIL_NOT_VERIFIED');
          return
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
       sendError(res, 'Refresh token is required', ErrorCodes.BAD_REQUEST, 'MISSING_REFRESH_TOKEN');
      return
    }

    logger.info('Token refresh attempt', { ip: req.ip });

    try {
      // Check if token is blacklisted
      const blacklistedToken = await BlacklistedToken.findOne({ token: refreshToken });
      if (blacklistedToken) {
        logger.security('blacklisted_token_usage_attempt', req.ip, req.get('User-Agent'), { token: refreshToken.substring(0, 20) + '...' });
         sendError(res, 'Token has been revoked', ErrorCodes.UNAUTHORIZED, 'TOKEN_REVOKED');
        return
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET as string) as { userId: string };

      if (!config.JWT_SECRET) {
        logger.error('JWT_SECRET is not defined in config');
        throw new AppError('Internal server configuration error', 500);
      }

      const tokenOptions: jwt.SignOptions = {
        expiresIn: config.JWT_EXPIRES_IN as any
      };

      // Generate new access token
      const token = jwt.sign(
        { userId: decoded.userId },
        config.JWT_SECRET,
        tokenOptions
      );

      logger.auth('token_refresh_success', decoded.userId);

      sendSuccess(res, { token }, 'Token refreshed successfully');

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        logger.security('invalid_refresh_token', req.ip, req.get('User-Agent'), { error: error.message });
         sendError(res, 'Invalid refresh token', ErrorCodes.UNAUTHORIZED, 'INVALID_REFRESH_TOKEN');
        return
      }
      
      logger.auth('token_refresh_failed', undefined, undefined, false, error);
      throw error;
    }
  }),

  // Forgot password
  forgotPassword: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
       sendError(res, 'Email is required', ErrorCodes.BAD_REQUEST, 'MISSING_EMAIL');
      return
    }

    logger.info('Password reset request', { email, ip: req.ip });

    const user = await User.findOne({ email });

    // Always return success message for security (don't reveal if user exists)
    const successMessage = 'If a user with that email exists, a password reset link has been sent';

    if (!user) {
      logger.security('password_reset_nonexistent_user', req.ip, req.get('User-Agent'), { email });
       sendSuccess(res, undefined, successMessage);
      return
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
      sendError(res, 'Token, password and confirm password are required', ErrorCodes.BAD_REQUEST, 'MISSING_FIELDS');
      return
    }

    if (password !== confirmPassword) {
       sendError(res, 'Passwords do not match', ErrorCodes.BAD_REQUEST, 'PASSWORD_MISMATCH');
       return
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
       sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
      return
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
         sendError(res, 'Password reset token is invalid or has expired', ErrorCodes.BAD_REQUEST, 'INVALID_RESET_TOKEN');
        return
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
  logout: asyncHandler(async (req: Request, res: Response): Promise<void> => {
      try {
        const { refreshToken } = req.body;
    
        if (!refreshToken) {
          sendError(res, 'Refresh token is required', ErrorCodes.BAD_REQUEST);
          return;
        }
    
        // Verify token first to get expiration
        const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as { exp: number };
        
        // Store in blacklist
        await BlacklistedToken.create({
          token: refreshToken,
          expiresAt: new Date(decoded.exp * 1000) // Convert JWT exp to Date
        });
    
        sendSuccess(res, null, 'Logout successful');
      } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
          sendError(res, 'Invalid refresh token', ErrorCodes.UNAUTHORIZED);
        } else {
          logger.error(`Logout error: ${error instanceof Error ? error.stack : error}`);
          sendError(res, 'Failed to logout', ErrorCodes.INTERNAL_SERVER_ERROR);
        }
      }
    }),
  
   googleAuth: (req: Request, res: Response, _next: NextFunction): Promise<void> => {
  return new Promise((resolve, reject) => {
    console.log('Google auth called');
    passport.authenticate('google', {
      scope: ['profile', 'email'],
      session: false
    })(req, res, (err: unknown) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
},

googleCallback: asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  return new Promise((resolve, reject) => {
    passport.authenticate('google', { session: false }, async (err: Error, user: any) => {
      try {
        if (err) {
          logger.error(`Google auth callback error: ${err}`);
          res.redirect(`${config.CLIENT_URL}/login?error=Google authentication failed`);
          return reject(err);
        }

        if (!user) {
          res.redirect(`${config.CLIENT_URL}/login?error=Could not authenticate with Google`);
          return reject(new Error('No user returned from Google authentication'));
        }

        // Generate JWT tokens
        const token = jwt.sign(
          { userId: user._id },
          config.JWT_SECRET,
          { expiresIn: config.JWT_EXPIRES_IN } as jwt.SignOptions  
        );
        
        const refreshToken = jwt.sign(
          { userId: user._id },
          config.JWT_REFRESH_SECRET,
          { expiresIn: config.JWT_REFRESH_EXPIRES_IN } as jwt.SignOptions
        );

        // Redirect to frontend with tokens
        res.redirect(
          `${config.CLIENT_URL}/social-auth-success?token=${token}&refreshToken=${refreshToken}`
        );
        resolve();
      } catch (error) {
        logger.error(`Failed to generate tokens: ${error}`);
        res.redirect(`${config.CLIENT_URL}/login?error=Authentication successful but token generation failed`);
        reject(error);
      }
    })(req, res, next);
  });
}),
  };