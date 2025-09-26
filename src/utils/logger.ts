// src/utils/logger.ts
import { config } from '../config/environment';

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

const LOG_LEVEL_MAP: Record<string, LogLevel> = {
  error: LogLevel.ERROR,
  warn: LogLevel.WARN,
  info: LogLevel.INFO,
  debug: LogLevel.DEBUG,
};

class Logger {
  private currentLevel: LogLevel;

  constructor() {
    this.currentLevel = LOG_LEVEL_MAP[config.LOG_LEVEL] || LogLevel.INFO;
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const baseMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    if (meta && Object.keys(meta).length > 0) {
      return `${baseMessage} ${JSON.stringify(meta, null, 2)}`;
    }
    
    return baseMessage;
  }

  private getColorCode(level: LogLevel): string {
    switch (level) {
      case LogLevel.ERROR:
        return '\x1b[31m'; // Red
      case LogLevel.WARN:
        return '\x1b[33m'; // Yellow
      case LogLevel.INFO:
        return '\x1b[36m'; // Cyan
      case LogLevel.DEBUG:
        return '\x1b[37m'; // White
      default:
        return '\x1b[0m'; // Reset
    }
  }

  private log(level: LogLevel, levelName: string, message: string, meta?: any): void {
    if (level > this.currentLevel) {
      return;
    }

    const formattedMessage = this.formatMessage(levelName, message, meta);
    const colorCode = this.getColorCode(level);
    const resetColor = '\x1b[0m';

    // Use appropriate console method based on level
    switch (level) {
      case LogLevel.ERROR:
        console.error(`${colorCode}${formattedMessage}${resetColor}`);
        break;
      case LogLevel.WARN:
        console.warn(`${colorCode}${formattedMessage}${resetColor}`);
        break;
      case LogLevel.INFO:
        console.info(`${colorCode}${formattedMessage}${resetColor}`);
        break;
      case LogLevel.DEBUG:
        console.debug(`${colorCode}${formattedMessage}${resetColor}`);
        break;
    }
  }

  error(message: string, meta?: any): void {
    this.log(LogLevel.ERROR, 'ERROR', message, meta);
  }

  warn(message: string, meta?: any): void {
    this.log(LogLevel.WARN, 'WARN', message, meta);
  }

  info(message: string, meta?: any): void {
    this.log(LogLevel.INFO, 'INFO', message, meta);
  }

  debug(message: string, meta?: any): void {
    this.log(LogLevel.DEBUG, 'DEBUG', message, meta);
  }

  // Convenience methods for common patterns
  http(method: string, url: string, statusCode: number, responseTime: number, ip?: string): void {
    const meta = {
      method,
      url,
      statusCode,
      responseTime: `${responseTime}ms`,
      ip: ip || 'unknown',
    };
    
    if (statusCode >= 500) {
      this.error(`HTTP ${statusCode} ${method} ${url}`, meta);
    } else if (statusCode >= 400) {
      this.warn(`HTTP ${statusCode} ${method} ${url}`, meta);
    } else {
      this.info(`HTTP ${statusCode} ${method} ${url}`, meta);
    }
  }

  email(action: string, recipient: string, success: boolean, messageId?: string, error?: any): void {
    const meta: any = { recipient, action };
    
    if (success && messageId) {
      meta.messageId = messageId;
      this.info(`✉️ Email ${action} successful`, meta);
    } else if (error) {
      meta.error = error instanceof Error ? error.message : String(error);
      meta.stack = error instanceof Error ? error.stack : undefined;
      this.error(`❌ Email ${action} failed`, meta);
    }
  }

  database(operation: string, collection: string, success: boolean, duration?: number, error?: any): void {
    const meta: any = { operation, collection };
    
    if (duration) {
      meta.duration = `${duration}ms`;
    }
    
    if (success) {
      this.debug(`📊 Database ${operation} on ${collection}`, meta);
    } else if (error) {
      meta.error = error instanceof Error ? error.message : String(error);
      meta.stack = error instanceof Error ? error.stack : undefined;
      this.error(`💥 Database ${operation} failed on ${collection}`, meta);
    }
  }

  auth(action: string, userId?: string, email?: string, success: boolean = true, error?: any): void {
    const meta: any = { action };
    
    if (userId) meta.userId = userId;
    if (email) meta.email = email;
    
    if (success) {
      this.info(`🔐 Auth: ${action}`, meta);
    } else if (error) {
      meta.error = error instanceof Error ? error.message : String(error);
      this.warn(`🚫 Auth failed: ${action}`, meta);
    }
  }

  security(event: string, ip?: string, userAgent?: string, details?: any): void {
    const meta: any = { event };
    
    if (ip) meta.ip = ip;
    if (userAgent) meta.userAgent = userAgent;
    if (details) meta.details = details;
    
    this.warn(`🛡️ Security event: ${event}`, meta);
  }

  performance(operation: string, duration: number, details?: any): void {
    const meta: any = { operation, duration: `${duration}ms` };
    
    if (details) meta.details = details;
    
    if (duration > 5000) {
      this.warn(`⚠️ Slow operation: ${operation}`, meta);
    } else if (duration > 1000) {
      this.info(`🐌 Operation took longer than expected: ${operation}`, meta);
    } else {
      this.debug(`⚡ Performance: ${operation}`, meta);
    }
  }
}

// Export singleton instance
export const logger = new Logger();

// Export for testing or custom instances
export { Logger };