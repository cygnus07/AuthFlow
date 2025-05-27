import { Response } from 'express';

// Standard HTTP status codes
export const HttpStatusCodes = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
} as const;

// Application-specific error codes for better error handling on frontend
export const ErrorCodes = {
  // Authentication & Authorization
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  INVALID_REFRESH_TOKEN: 'INVALID_REFRESH_TOKEN',
  MISSING_REFRESH_TOKEN: 'MISSING_REFRESH_TOKEN',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  ACCOUNT_INACTIVE: 'ACCOUNT_INACTIVE',
  ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',

  // Validation
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  MISSING_FIELDS: 'MISSING_FIELDS',
  INVALID_FORMAT: 'INVALID_FORMAT',
  WEAK_PASSWORD: 'WEAK_PASSWORD',
  PASSWORD_MISMATCH: 'PASSWORD_MISMATCH',
  SAME_PASSWORD: 'SAME_PASSWORD',
  INVALID_CURRENT_PASSWORD: 'INVALID_CURRENT_PASSWORD',

  // User Management
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  USER_ALREADY_EXISTS: 'USER_ALREADY_EXISTS',
  EMAIL_IN_USE: 'EMAIL_IN_USE',
  USERNAME_TAKEN: 'USERNAME_TAKEN',
  DUPLICATE_FIELD: 'DUPLICATE_FIELD',

  // Email & Verification
  MISSING_EMAIL: 'MISSING_EMAIL',
  INVALID_VERIFICATION_CODE: 'INVALID_VERIFICATION_CODE',
  VERIFICATION_CODE_EXPIRED: 'VERIFICATION_CODE_EXPIRED',
  USER_NOT_FOUND_OR_VERIFIED: 'USER_NOT_FOUND_OR_VERIFIED',
  INVALID_RESET_TOKEN: 'INVALID_RESET_TOKEN',
  EMAIL_SEND_FAILED: 'EMAIL_SEND_FAILED',

  // Generic HTTP errors
  BAD_REQUEST: 'BAD_REQUEST',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  UNPROCESSABLE_ENTITY: 'UNPROCESSABLE_ENTITY',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',

  // File & Upload
  FILE_TOO_LARGE: 'FILE_TOO_LARGE',
  INVALID_FILE_TYPE: 'INVALID_FILE_TYPE',
  UPLOAD_FAILED: 'UPLOAD_FAILED',

  // Database
  DATABASE_ERROR: 'DATABASE_ERROR',
  RECORD_NOT_FOUND: 'RECORD_NOT_FOUND',
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // External Services
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  PAYMENT_FAILED: 'PAYMENT_FAILED',

  // Generic
  UNKNOWN_ERROR: 'UNKNOWN_ERROR'
} as const;

// Standard API response interface
interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  error?: {
    code: string;
    details?: any;
    timestamp?: string;
    requestId?: string;
  };
  meta?: {
    timestamp: string;
    version?: string;
    requestId?: string;
  };
}

// Pagination interface for list responses
export interface PaginationMeta {
  total: number;
  page: number;
  limit: number;
  pages: number;
  hasNext?: boolean;
  hasPrev?: boolean;
}

// Success response with optional data
export const sendSuccess = <T = any>(
  res: Response,
  data?: T,
  message: string = 'Success',
  statusCode: number = HttpStatusCodes.OK,
  meta?: any
): void => {
  const response: ApiResponse<T> = {
    success: true,
    message,
    ...(data !== undefined && { data }),
    meta: {
      timestamp: new Date().toISOString(),
      ...(meta && meta)
    }
  };

  res.status(statusCode).json(response);
};

// Error response with error details
export const sendError = (
  res: Response,
  message: string = 'An error occurred',
  statusCode: number = HttpStatusCodes.INTERNAL_SERVER_ERROR,
  errorCode: string = ErrorCodes.UNKNOWN_ERROR,
  details?: any,
  requestId?: string
): void => {
  const response: ApiResponse = {
    success: false,
    message,
    error: {
      code: errorCode,
      ...(details && { details }),
      timestamp: new Date().toISOString(),
      ...(requestId && { requestId })
    },
    meta: {
      timestamp: new Date().toISOString(),
      ...(requestId && { requestId })
    }
  };

  res.status(statusCode).json(response);
};

// Validation error response (for form validation failures)
export const sendValidationError = (
  res: Response,
  errors: Array<{ field: string; message: string; value?: any }>,
  message: string = 'Validation failed'
): void => {
  sendError(
    res,
    message,
    HttpStatusCodes.UNPROCESSABLE_ENTITY,
    ErrorCodes.VALIDATION_ERROR,
    { validationErrors: errors }
  );
};

// Paginated success response
export const sendPaginatedSuccess = <T = any>(
  res: Response,
  data: T[],
  pagination: PaginationMeta,
  message: string = 'Data retrieved successfully',
  statusCode: number = HttpStatusCodes.OK
): void => {
  const enhancedPagination = {
    ...pagination,
    hasNext: pagination.page < pagination.pages,
    hasPrev: pagination.page > 1
  };

  sendSuccess(
    res,
    {
      items: data,
      pagination: enhancedPagination
    },
    message,
    statusCode
  );
};

// Not found response
export const sendNotFound = (
  res: Response,
  resource: string = 'Resource',
  resourceId?: string
): void => {
  const message = resourceId 
    ? `${resource} with ID '${resourceId}' not found`
    : `${resource} not found`;
    
  sendError(
    res,
    message,
    HttpStatusCodes.NOT_FOUND,
    ErrorCodes.NOT_FOUND
  );
};

// Unauthorized response
export const sendUnauthorized = (
  res: Response,
  message: string = 'Authentication required'
): void => {
  sendError(
    res,
    message,
    HttpStatusCodes.UNAUTHORIZED,
    ErrorCodes.UNAUTHORIZED
  );
};

// Forbidden response
export const sendForbidden = (
  res: Response,
  message: string = 'Access denied'
): void => {
  sendError(
    res,
    message,
    HttpStatusCodes.FORBIDDEN,
    ErrorCodes.FORBIDDEN
  );
};

// Rate limit exceeded response
export const sendRateLimitExceeded = (
  res: Response,
  retryAfter?: number,
  message: string = 'Too many requests'
): void => {
  if (retryAfter) {
    res.set('Retry-After', retryAfter.toString());
  }
  
  sendError(
    res,
    message,
    HttpStatusCodes.TOO_MANY_REQUESTS,
    ErrorCodes.RATE_LIMIT_EXCEEDED,
    retryAfter ? { retryAfter } : undefined
  );
};

// Conflict response (for duplicate resources)
export const sendConflict = (
  res: Response,
  resource: string,
  field?: string,
  value?: string
): void => {
  const message = field && value
    ? `${resource} with ${field} '${value}' already exists`
    : `${resource} already exists`;
    
  sendError(
    res,
    message,
    HttpStatusCodes.CONFLICT,
    ErrorCodes.CONFLICT
  );
};

// Bad request response
export const sendBadRequest = (
  res: Response,
  message: string = 'Invalid request',
  details?: any
): void => {
  sendError(
    res,
    message,
    HttpStatusCodes.BAD_REQUEST,
    ErrorCodes.BAD_REQUEST,
    details
  );
};

// Internal server error response
export const sendInternalError = (
  res: Response,
  message: string = 'Internal server error',
  requestId?: string
): void => {
  sendError(
    res,
    message,
    HttpStatusCodes.INTERNAL_SERVER_ERROR,
    ErrorCodes.INTERNAL_SERVER_ERROR,
    undefined,
    requestId
  );
};

// Helper to map HTTP status codes to error codes
export const getErrorCodeFromStatus = (statusCode: number): string => {
  switch (statusCode) {
    case HttpStatusCodes.BAD_REQUEST:
      return ErrorCodes.BAD_REQUEST;
    case HttpStatusCodes.UNAUTHORIZED:
      return ErrorCodes.UNAUTHORIZED;
    case HttpStatusCodes.FORBIDDEN:
      return ErrorCodes.FORBIDDEN;
    case HttpStatusCodes.NOT_FOUND:
      return ErrorCodes.NOT_FOUND;
    case HttpStatusCodes.CONFLICT:
      return ErrorCodes.CONFLICT;
    case HttpStatusCodes.UNPROCESSABLE_ENTITY:
      return ErrorCodes.UNPROCESSABLE_ENTITY;
    case HttpStatusCodes.TOO_MANY_REQUESTS:
      return ErrorCodes.RATE_LIMIT_EXCEEDED;
    case HttpStatusCodes.INTERNAL_SERVER_ERROR:
      return ErrorCodes.INTERNAL_SERVER_ERROR;
    default:
      return ErrorCodes.UNKNOWN_ERROR;
  }
};

// Type exports for better TypeScript support
export type ErrorCode = typeof ErrorCodes[keyof typeof ErrorCodes];
export type HttpStatusCode = typeof HttpStatusCodes[keyof typeof HttpStatusCodes];

// Export the response interface for use in other files
