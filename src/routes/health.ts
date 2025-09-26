import { Router, Request, Response } from 'express';
import { isDatabaseHealthy } from '../config/db';
import { config } from '../config/environment';
import { asyncHandler } from '../middleware/errorHandler';

const router = Router();

interface HealthCheck {
  status: 'OK' | 'ERROR';
  timestamp: string;
  uptime: number;
  environment: string;
  version: string;
  database: {
    status: 'connected' | 'disconnected';
    type: string;
  };
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  system: {
    platform: string;
    nodeVersion: string;
  };
}

// Basic health check
router.get('/', asyncHandler(async (_req: Request, res: Response) => {
  const memoryUsage = process.memoryUsage();
  const totalMemory = memoryUsage.heapTotal;
  const usedMemory = memoryUsage.heapUsed;
  
  const isDatabaseConnected = await isDatabaseHealthy();
  
  const healthData: HealthCheck = {
    status: isDatabaseConnected ? 'OK' : 'ERROR',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: config.NODE_ENV,
    version: '1.0.0',
    database: {
      status: isDatabaseConnected ? 'connected' : 'disconnected',
      type: config.DATABASE_TYPE,
    },
    memory: {
      used: Math.round(usedMemory / 1024 / 1024), // MB
      total: Math.round(totalMemory / 1024 / 1024), // MB
      percentage: Math.round((usedMemory / totalMemory) * 100),
    },
    system: {
      platform: process.platform,
      nodeVersion: process.version,
    },
  };

  const statusCode = healthData.status === 'OK' ? 200 : 503;
  res.status(statusCode).json(healthData);
}));

// Detailed health check
router.get('/detailed', asyncHandler(async (_req: Request, res: Response) => {
  const memoryUsage = process.memoryUsage();
  const isDatabaseConnected = await isDatabaseHealthy();
  
  const detailedHealth = {
    status: isDatabaseConnected ? 'OK' : 'ERROR',
    timestamp: new Date().toISOString(),
    services: {
      database: {
        status: isDatabaseConnected ? 'healthy' : 'unhealthy',
        type: config.DATABASE_TYPE,
        lastChecked: new Date().toISOString(),
      },
      // Add other service checks here
      // redis: { status: 'healthy' },
      // externalApi: { status: 'healthy' },
    },
    system: {
      uptime: process.uptime(),
      memory: {
        rss: Math.round(memoryUsage.rss / 1024 / 1024),
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        external: Math.round(memoryUsage.external / 1024 / 1024),
      },
      cpu: {
        usage: process.cpuUsage(),
      },
      environment: config.NODE_ENV,
      nodeVersion: process.version,
      platform: process.platform,
      architecture: process.arch,
    },
  };

  const statusCode = detailedHealth.status === 'OK' ? 200 : 503;
  res.status(statusCode).json(detailedHealth);
}));

// Readiness probe (for Kubernetes)
router.get('/ready', asyncHandler(async (_req: Request, res: Response) => {
  const isDatabaseConnected = await isDatabaseHealthy();
  
  if (isDatabaseConnected) {
    res.status(200).json({ status: 'ready' });
  } else {
    res.status(503).json({ status: 'not ready', reason: 'database not connected' });
  }
}));

// Liveness probe (for Kubernetes)
router.get('/live', (_req, res: Response) => {
  res.status(200).json({ status: 'alive' });
});

export default router;