import { Response } from 'express';
import bcrypt from 'bcryptjs';
import { emailService } from '../services/emailService';
import User from '../models/userModel';
import { AppError, asyncHandler } from '../middleware/errorHandler';
import { sendSuccess, sendError, ErrorCodes } from '../utils/apiResponse'
import { logger } from '../utils/logger';
import { AuthenticatedRequest } from '../types/userTypes';

import {
  UpdateProfileInput,
  ChangePasswordInput,
} from '../validators/userValidator';



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
  // Get current user profile
  getProfile: asyncHandler(async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const user = req.user;

    if (!user) {
      logger.error('User not found in authenticated request');
       sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      return
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
       sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      return
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
         sendError(res, 'Email already in use', ErrorCodes.CONFLICT, 'EMAIL_IN_USE');
        return
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
         sendError(res, 'Username already taken', ErrorCodes.CONFLICT, 'USERNAME_TAKEN');
        return
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
         sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
        return
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
       sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      return
    }
    
    const userId = req.user._id;
    logger.info('Password change attempt', { userId: userId.toString() });

    if (currentPassword === newPassword) {
       sendError(res, 'New password must be different from current password', ErrorCodes.BAD_REQUEST, 'SAME_PASSWORD');
      return
    }

    // Validate new password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.isValid) {
       sendError(res, passwordValidation.message!, ErrorCodes.BAD_REQUEST, 'WEAK_PASSWORD');
      return
    }

    try {
      // Find user with password
      const user = await User.findById(userId).select('+password');
      if (!user) {
         sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
        return
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
         sendError(res, 'Current password is incorrect', ErrorCodes.UNAUTHORIZED, 'INVALID_CURRENT_PASSWORD');
        return
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

};