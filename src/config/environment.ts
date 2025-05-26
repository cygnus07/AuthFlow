import { z } from 'zod';

// Environment schema validation
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  
  // Database configuration
  DATABASE_TYPE: z.enum(['mongodb', 'postgresql']).default('mongodb'),
  
  // MongoDB configuration
  MONGODB_URI: z.string().optional(),
  
  // PostgreSQL configuration
  POSTGRES_HOST: z.string().optional(),
  POSTGRES_PORT: z.string().transform(Number).optional(),
  POSTGRES_USER: z.string().optional(),
  POSTGRES_PASSWORD: z.string().optional(),
  POSTGRES_DATABASE: z.string().optional(),
  DATABASE_URL: z.string().optional(),
  
  // Security
  JWT_SECRET: z.string().optional(),
  JWT_EXPIRES_IN: z.string().default('24h'),
  BCRYPT_ROUNDS: z.string().transform(Number).default('12'),
  
  // CORS
  CORS_ORIGIN: z.string().or(z.array(z.string())).default('*'),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  
  // Redis (optional)
  REDIS_URL: z.string().optional(),
  
  // External APIs
  API_BASE_URL: z.string().url().optional(),
});

type Config = z.infer<typeof envSchema>;

function validateEnvironment(): Config {
  try {
    return envSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('❌ Invalid environment configuration:');
      error.errors.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
      });
    }
    process.exit(1);
  }
}

export const config = validateEnvironment();

// Database connection string builders
export const getDatabaseConnectionString = (): string => {
  if (config.DATABASE_TYPE === 'mongodb') {
    if (!config.MONGODB_URI) {
      throw new Error('MONGODB_URI is required when DATABASE_TYPE is mongodb');
    }
    return config.MONGODB_URI;
  }
  
  if (config.DATABASE_TYPE === 'postgresql') {
    if (config.DATABASE_URL) {
      return config.DATABASE_URL;
    }
    
    const { POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DATABASE } = config;
    
    if (!POSTGRES_HOST || !POSTGRES_USER || !POSTGRES_PASSWORD || !POSTGRES_DATABASE) {
      throw new Error('PostgreSQL connection parameters are incomplete');
    }
    
    const port = POSTGRES_PORT || 5432;
    return `postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${port}/${POSTGRES_DATABASE}`;
  }
  
  throw new Error('Invalid DATABASE_TYPE');
};

export default config;