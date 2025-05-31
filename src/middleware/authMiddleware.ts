import { Request, Response, NextFunction, RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/environment';
import { ErrorCodes, sendError } from '../utils/apiResponse';
import User from '../models/userModel';
import { logger } from '../utils/logger';
import BlacklistedToken from '../models/blacklistedTokenModel';
import { AuthenticatedRequest, AuthUser } from '../types/userTypes';

declare global {
  namespace Express {
    interface User extends AuthUser {}
    interface Request {
      user?: AuthUser;
      token?: string;
    }
  }
}

export const withAuth = <T extends Request>(
  handler: (req: T & AuthenticatedRequest, res: Response, next?: NextFunction) => Promise<void> | void
): RequestHandler => {
  return async (req, res, next) => {
    try {
      await handler(req as T & AuthenticatedRequest, res, next);
    } catch (error) {
      next(error);
    }
  };
};

const authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      sendError(res, 'Authentication required', ErrorCodes.UNAUTHORIZED, 'MISSING_AUTH_HEADER');
      return;
    }
    
    const token = authHeader.split(' ')[1];

    if (!token) {
      sendError(res, 'Authentication token missing', ErrorCodes.UNAUTHORIZED, 'MISSING_TOKEN');
      return;
    }

    if (!config.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined');
    }

    const decoded = jwt.verify(token, config.JWT_SECRET) as any;
    const user = await User.findById(decoded.userId);

    const isBlacklisted = await BlacklistedToken.findOne({ token });
    if (isBlacklisted) {
      sendError(res, 'Token revoked', ErrorCodes.UNAUTHORIZED, 'TOKEN_REVOKED');
      return;
    }
    
    if (!user) {
      sendError(res, 'User not found', ErrorCodes.UNAUTHORIZED, 'USER_NOT_FOUND');
      return;
    }
    
    req.user = user as unknown as AuthUser;
    req.token = token;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      if (error.name === 'TokenExpiredError') {
        sendError(res, 'Token expired', ErrorCodes.UNAUTHORIZED, 'TOKEN_EXPIRED');
      } else {
        sendError(res, 'Invalid token', ErrorCodes.UNAUTHORIZED, 'INVALID_TOKEN');
      }
      return;
    }
    
    logger.error(`Auth middleware error: ${error}`);
    next(error);
  }
};

const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      sendError(res, 'Authentication required', ErrorCodes.UNAUTHORIZED, 'UNAUTHORIZED');
      return;
    }
    
    if (!roles.includes(req.user.role)) {
      sendError(res, 'Not authorized to access this resource', ErrorCodes.FORBIDDEN, 'FORBIDDEN');
      return;
    }
    
    next();
  };
};

export const auth = {
  authenticate,
  authorize,
  admin: [authenticate, authorize('admin')],
  user: [authenticate, authorize('user')],
};

export { authenticate, authorize };