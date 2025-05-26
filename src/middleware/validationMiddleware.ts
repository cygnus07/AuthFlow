import {  RequestHandler } from 'express';
import { z, ZodError } from 'zod';
import { ErrorCodes } from '../utils/apiResponse';

declare global {
  namespace Express {
    interface Request {
      validatedData?: any;
    }
  }
}

export const validate = <T extends z.ZodTypeAny>(
  schema: T, 
  source: 'body' | 'params' | 'query' = 'body'
): RequestHandler => {
  return async (req, res, next) => {
    try {
      let data;
      if (source === 'body') {
        data = req.body;
      } else if (source === 'params') {
        data = req.params;
      } else if (source === 'query') {
        data = req.query;
      }

      req.validatedData = await schema.parseAsync(data);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        // Don't return a value here - just send the response
        res.status(400).json({
          success: false,
          code: ErrorCodes.VALIDATION_ERROR,
          message: 'Validation failed',
          errors: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message
          }))
        });
        // Don't call next() here since you've already sent a response 
        return;
      }
      next(error);
    }
  };
};