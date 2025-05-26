import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { emailService } from '../services/emailService.js';
import User from '../models/userModel.js';
import { config } from '../config/environment.js';
import { AppError, asyncHandler } from '../middleware/errorHandler.js';
import BlacklistedToken from '../models/blacklistedTokenModel.js';
import { AuthenticatedRequest } from '../types/userTypes.js';
import { UserRole, AccountStatus } from '../types/userTypes.js';

import {
  RegisterInput,
  LoginInput,
  RefreshTokenInput,
  UpdateProfileInput,
  ChangePasswordInput,
  AdminUpdateUserInput
} from '../validators/userValidator.js';
// Helper function to generate OTP
const generateOTP = (): string => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Helper function to generate JWT tokens
// Helper function to generate JWT tokens
const generateTokens = (userId: string) => {
  if (!config.JWT_SECRET || !config.JWT_REFRESH_SECRET) {
    throw new Error("JWT secrets are not defined in config");
  }

  // Ensure the secrets are strings
  const jwtSecret = config.JWT_SECRET as string;
  const refreshSecret = config.JWT_REFRESH_SECRET as string;

// ...existing code...
const tokenOptions: jwt.SignOptions = { expiresIn: Number(config.JWT_EXPIRES_IN) };
const refreshOptions: jwt.SignOptions = { expiresIn: Number(config.JWT_REFRESH_EXPIRES_IN) };
// ...existing code...

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

  return { token, refreshToken };
};


// Helper function to create user response (removes sensitive fields)
const createUserResponse = (user: any) => {
  const userObj = user.toObject ? user.toObject() : user;
  const { password, refreshToken, passwordResetToken, emailVerificationToken, ...safeUser } = userObj;
  return safeUser;
};

export const userController = {
  // Register new user
  register: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { firstName, lastName, username, email, password, role } = req.body as RegisterInput;
    
    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [
        { email },
        ...(username ? [{ username }] : [])
      ]
    });

    if (existingUser) {
      if (existingUser.email === email) {
        if (existingUser.emailVerified) {
          throw new AppError('Email already in use', 409);
        } else {
          throw new AppError('Email already registered but not verified. Check your email for verification code.', 409);
        }
      }
      if (username && existingUser.username === username) {
        throw new AppError('Username already taken', 409);
      }
    }

    // Generate OTP for email verification
    const otp = generateOTP();
    const emailVerificationToken = crypto
      .createHash('sha256')
      .update(otp)
      .digest('hex');

    // Create new user
    const user = new User({
      firstName,
      lastName,
      username,
      email,
      password: await bcrypt.hash(password, 12),
      role: role || UserRole.USER,
      emailVerified: false,
      emailVerificationToken,
      passwordResetExpires: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    });

    await user.save();

    // Send verification email
    try {
      await emailService.sendVerificationEmail(email, firstName || username || 'User', otp);
    } catch (error) {
      console.error('Failed to send verification email:', error);
      // Don't fail registration if email fails
    }

    res.status(201).json({
      success: true,
      message: 'Registration successful. Please check your email for verification instructions.',
      data: {
        user: createUserResponse(user)
      }
    });
  }),

  // Verify email
  verifyEmail: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email, otp } = req.body;

    if (!email || !otp) {
      throw new AppError('Email and OTP are required', 400);
    }

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
      throw new AppError('Invalid, expired, or already verified code', 400);
    }

    // Generate tokens
    const { token, refreshToken } = generateTokens(user._id.toString());

    // Send welcome email
    try {
      await emailService.sendWelcomeEmail(user.email, user.firstName || user.username || 'User');
    } catch (error) {
      console.error('Failed to send welcome email:', error);
    }

    res.json({
      success: true,
      message: 'Email verified successfully',
      data: {
        user: createUserResponse(user),
        token,
        refreshToken
      }
    });
  }),

  // Resend verification email
  resendVerificationEmail: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
      throw new AppError('Email is required', 400);
    }

    const user = await User.findOne({ email, emailVerified: false });
    if (!user) {
      throw new AppError('User not found or already verified', 400);
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
    await emailService.sendVerificationEmail(email, user.firstName || user.username || 'User', otp);

    res.json({
      success: true,
      message: 'Verification email sent successfully'
    });
  }),

  // Login user
  login: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body as LoginInput;

    // Find user and include password for comparison
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      throw new AppError('Invalid credentials', 401);
    }

    // Check if account is active
    if (user.status !== AccountStatus.ACTIVE) {
      throw new AppError('Account is suspended or inactive', 403);
    }

    if (!user.password) {
  throw new Error('Password not set for this user');
}


    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new AppError('Invalid credentials', 401);
    }

    // Check if email is verified
    if (!user.emailVerified) {
      throw new AppError('Email not verified. Please check your email for verification instructions.', 403);
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate tokens
    const { token, refreshToken } = generateTokens(user._id.toString());

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: createUserResponse(user),
        token,
        refreshToken
      }
    });
  }),

  // Refresh token
  refreshToken: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body as RefreshTokenInput;

    if (!refreshToken) {
      throw new AppError('Refresh token is required', 400);
    }

    // Check if token is blacklisted
    const blacklistedToken = await BlacklistedToken.findOne({ token: refreshToken });
    if (blacklistedToken) {
      throw new AppError('Token has been revoked', 401);
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as { userId: string };

    if (!config.JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined');
}


    // Generate new access token
const token = jwt.sign(
  { userId: decoded.userId },
  config.JWT_SECRET as string, // Explicitly cast to string
  { expiresIn: config.JWT_EXPIRES_IN } as jwt.SignOptions // Explicitly type options
);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: { token }
    });
  }),

  // Forgot password
  forgotPassword: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    if (!email) {
      throw new AppError('Email is required', 400);
    }

    const user = await User.findOne({ email });

    // Don't reveal if user exists for security
    if (!user) {
       res.json({
        success: true,
        message: 'If a user with that email exists, a password reset link has been sent'
      });
      return;
    }

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
    try {
      await emailService.sendPasswordResetEmail(
        user.email,
        user.firstName || user.username || 'User',
        resetToken
      );

      res.json({
        success: true,
        message: 'Password reset link sent to your email. The link is valid for 1 hour.'
      });
    } catch (error) {
      // Clean up reset token if email fails
      user.passwordResetToken = undefined as any
      user.passwordResetExpires = undefined as any
      await user.save();
      
      throw new AppError('Failed to send password reset email', 500);
    }
  }),

  // Reset password
  resetPassword: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { token, password, confirmPassword } = req.body;

    if (!token || !password || !confirmPassword) {
      throw new AppError('Token, password and confirm password are required', 400);
    }

    if (password !== confirmPassword) {
      throw new AppError('Passwords do not match', 400);
    }

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
      throw new AppError('Password reset token is invalid or has expired', 400);
    }

    // Update password
    user.password = await bcrypt.hash(password, 12);
    user.passwordResetToken = undefined as any;
    user.passwordResetExpires = undefined as any
    user.passwordChangedAt = new Date();
    await user.save();

    // Send confirmation email
    try {
      await emailService.sendPasswordChangeNotification(
        user.email,
        user.firstName || user.username || 'User'
      );
    } catch (error) {
      console.error('Failed to send password change notification:', error);
    }

    res.json({
      success: true,
      message: 'Your password has been reset successfully. You can now log in with your new password.'
    });
  }),

  // Get current user profile
  getProfile: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const user = req.user;

    if (!user) {
      throw new AppError('User not found', 404);
    }

    res.json({
      success: true,
      message: 'User profile retrieved successfully',
      data: {
        user: createUserResponse(user)
      }
    });
  }),

  // Update user profile
  updateProfile: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { firstName, lastName, username, email, phone } = req.body as UpdateProfileInput;
    const userId = req.user._id;

    // Check if email or username is being changed and already exists
    const updateData: any = {};
    
    if (email && email !== req.user.email) {
      const existingUser = await User.findOne({ email, _id: { $ne: userId } });
      if (existingUser) {
        throw new AppError('Email already in use', 409);
      }
      updateData.email = email;
      updateData.emailVerified = false; // Require re-verification if email changes
    }

    if (username && username !== req.user.username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        throw new AppError('Username already taken', 409);
      }
      updateData.username = username;
    }

    // Add other fields
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (phone !== undefined) updateData.phone = phone;

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      throw new AppError('User not found', 404);
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: createUserResponse(updatedUser)
      }
    });
  }),

  // Change password
  changePassword: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const { currentPassword, newPassword } = req.body as ChangePasswordInput;
    const userId = req.user._id;

    if (currentPassword === newPassword) {
      throw new AppError('New password must be different from current password', 400);
    }

    // Find user with password
    const user = await User.findById(userId).select('+password');
    if (!user) {
      throw new AppError('User not found', 404);
    }

    if (!user.password) {
  throw new Error('Password not set for this user');
}


    // Check current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      throw new AppError('Current password is incorrect', 401);
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
    } catch (error) {
      console.error('Failed to send password change notification:', error);
    }

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  }),

  // Admin: Get all users
  getAllUsers: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const page = parseInt(req.query['page'] as string) || 1;
    const limit = parseInt(req.query['limit'] as string) || 10;
    const skip = (page - 1) * limit;

    const users = await User.find()
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments();

    res.json({
      success: true,
      message: 'Users retrieved successfully',
      data: {
        users: users.map(createUserResponse),
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      }
    });
  }),

  // Admin: Get user by ID
  getUserById: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];

    const user = await User.findById(userId);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    res.json({
      success: true,
      message: 'User retrieved successfully',
      data: {
        user: createUserResponse(user)
      }
    });
  }),

  // Admin: Update user
  updateUser: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];
    const { firstName, lastName, username, email, role, status } = req.body as AdminUpdateUserInput;

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
        throw new AppError(`${field} already in use`, 409);
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { firstName, lastName, username, email, role, status },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      throw new AppError('User not found', 404);
    }

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: createUserResponse(updatedUser)
      }
    });
  }),

  // Admin: Delete user
  deleteUser: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const userId = req.params['id'];

    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      throw new AppError('User not found', 404);
    }

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  }),

  // Logout user
  logout: asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      throw new AppError('Refresh token is required', 400);
    }

    // Verify token to get expiration
    const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as { exp: number };

    // Add to blacklist
    await BlacklistedToken.create({
      token: refreshToken,
      expiresAt: new Date(decoded.exp * 1000)
    });

    res.json({
      success: true,
      message: 'Logout successful'
    });
  }),

  // Google Authentication
  googleAuth: (req: Request, res: Response, next: any) => {
    passport.authenticate('google', {
      scope: ['profile', 'email']
    })(req, res, next);
  },

  googleCallback: (req: Request, res: Response, next: any) => {
    passport.authenticate('google', { session: false }, async (err: Error, user: any) => {
      if (err) {
        console.error('Google auth callback error:', err);
        return res.redirect(`${config.CLIENT_URL}/login?error=Google authentication failed`);
      }

      if (!user) {
        return res.redirect(`${config.CLIENT_URL}/login?error=Could not authenticate with Google`);
      }

      try {
        // Generate JWT tokens
        const { token, refreshToken } = generateTokens(user._id.toString());

        // Redirect to frontend with tokens
        return res.redirect(
          `${config.CLIENT_URL}/social-auth-success?token=${token}&refreshToken=${refreshToken}`
        );
      } catch (error) {
        console.error('Failed to generate tokens:', error);
        return res.redirect(`${config.CLIENT_URL}/login?error=Authentication successful but token generation failed`);
      }
    })(req, res, next);
  }
};