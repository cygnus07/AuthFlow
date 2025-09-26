import { Request, Response, NextFunction } from 'express';
import { config } from '../config/environment';

export interface RequestLog {
  method: string;
  url: string;
  statusCode: number;
  responseTime: number;
  ip: string;
  userAgent?: string | undefined;
  timestamp: string;
}

export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();

  // Skip logging for health checks in production
  if (config.NODE_ENV === 'production' && req.url === '/health') {
    return next();
  }

  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    
    const logData: RequestLog = {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime,
      ip: req.ip || req.connection.remoteAddress || 'unknown',
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    };

    // Color coding for different status codes
    const getStatusColor = (status: number): string => {
      if (status >= 500) return '\x1b[31m'; // Red
      if (status >= 400) return '\x1b[33m'; // Yellow
      if (status >= 300) return '\x1b[36m'; // Cyan
      if (status >= 200) return '\x1b[32m'; // Green
      return '\x1b[0m'; // Reset
    };

    const resetColor = '\x1b[0m';
    const statusColor = getStatusColor(logData.statusCode);

    console.log(
      `${statusColor}${logData.method} ${logData.url} ${logData.statusCode}${resetColor} - ${logData.responseTime}ms - ${logData.ip}`
    );

    // Log additional details for errors
    if (logData.statusCode >= 400) {
      console.error('📋 Request details:', {
        headers: req.headers,
        body: req.body,
        params: req.params,
        query: req.query,
      });
    }
  });

  next();
};