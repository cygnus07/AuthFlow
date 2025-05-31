import { Request, Response } from 'express';
import User from '../models/userModel';
import { asyncHandler } from '../middleware/errorHandler';
import { sendSuccess, sendError, ErrorCodes } from '../utils/apiResponse'
import { logger } from '../utils/logger';


import {
  AdminUpdateUserInput
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


export const adminController = {
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
       sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
      return
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
         sendError(res, `${field} already in use`, ErrorCodes.CONFLICT, 'DUPLICATE_FIELD');
        return
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
         sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
        return
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
         sendError(res, 'User not found', ErrorCodes.NOT_FOUND, 'USER_NOT_FOUND');
        return
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
};