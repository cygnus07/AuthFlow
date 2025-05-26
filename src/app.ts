import express, { Application, RequestHandler, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { config } from '@/config/environment';
import { errorHandler, notFoundHandler } from '@/middleware/errorHandler';
import { requestLogger } from '@/middleware/requestLogger';
import apiRoutes from '@/routes';

class App {
  public app: Application;

  constructor() {
    this.app = express();
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeMiddlewares(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
    }));

    // CORS configuration
    this.app.use(cors({
      origin: config.CORS_ORIGIN,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: config.NODE_ENV === 'production' ? 100 : 1000, // Limit each IP
      message: {
        error: 'Too many requests from this IP, please try again later.',
      },
      standardHeaders: true,
      legacyHeaders: false,
    });
    this.app.use(limiter);

    // Compression middleware
    this.app.use(compression());

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Logging middleware
    if (config.NODE_ENV !== 'test') {
      this.app.use(morgan('combined'));
    }
    this.app.use(requestLogger as RequestHandler);

    // Health check middleware
    this.app.use('/health', (_req, res) => {
      res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.NODE_ENV,
      });
    });
  }

  private initializeRoutes(): void {
    // Root route
    this.app.get('/', (_req ,res: Response) => {
      res.status(200).json({
        status: 'API running',
        message: 'Welcome to the Node.js TypeScript Express API',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
      });
    });

    // API routes
    this.app.use('/api', apiRoutes);
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use(notFoundHandler as RequestHandler);
    
    // Global error handler
    this.app.use(errorHandler);
  }

  public listen(): void {
    const port = config.PORT;
    this.app.listen(port, () => {
      console.log(`🚀 Server running on port ${port} in ${config.NODE_ENV} mode`);
      console.log(`📊 Health check available at http://localhost:${port}/health`);
    });
  }
}

export default App;