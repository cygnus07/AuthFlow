import mongoose, { ConnectOptions } from 'mongoose';
import { Pool } from 'pg';
import { PrismaClient } from '@prisma/client';
import { config, getDatabaseConnectionString } from './environment';

// MongoDB connection
class MongoDBConnection {
  private static instance: MongoDBConnection;
  private isConnected: boolean = false;

  private constructor() {}

  public static getInstance(): MongoDBConnection {
    if (!MongoDBConnection.instance) {
      MongoDBConnection.instance = new MongoDBConnection();
    }
    return MongoDBConnection.instance;
  }

  public async connect(): Promise<void> {
    if (this.isConnected) {
      console.log('📦 MongoDB already connected');
      return;
    }

    try {
      const connectionString = getDatabaseConnectionString();
      
      const options: ConnectOptions = {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferCommands: false,
        // bufferMaxEntries: 0,
      };

      await mongoose.connect(connectionString, options);
      
      this.isConnected = true;
      console.log('🍃 MongoDB connected successfully');

      // Handle connection events
      mongoose.connection.on('error', (error) => {
        console.error('❌ MongoDB connection error:', error);
        this.isConnected = false;
      });

      mongoose.connection.on('disconnected', () => {
        console.log('📦 MongoDB disconnected');
        this.isConnected = false;
      });

      mongoose.connection.on('reconnected', () => {
        console.log('🔄 MongoDB reconnected');
        this.isConnected = true;
      });

    } catch (error) {
      console.error('❌ MongoDB connection failed:', error);
      throw error;
    }
  }

  public async disconnect(): Promise<void> {
    if (!this.isConnected) {
      return;
    }

    try {
      await mongoose.disconnect();
      this.isConnected = false;
      console.log('📦 MongoDB disconnected gracefully');
    } catch (error) {
      console.error('❌ Error disconnecting from MongoDB:', error);
      throw error;
    }
  }

  public getConnection() {
    return mongoose.connection;
  }

  public isHealthy(): boolean {
    return this.isConnected && mongoose.connection.readyState === 1;
  }
}

// PostgreSQL connection with pg
class PostgreSQLConnection {
  private static instance: PostgreSQLConnection;
  private pool: Pool | null = null;

  private constructor() {}

  public static getInstance(): PostgreSQLConnection {
    if (!PostgreSQLConnection.instance) {
      PostgreSQLConnection.instance = new PostgreSQLConnection();
    }
    return PostgreSQLConnection.instance;
  }

  public async connect(): Promise<void> {
    if (this.pool) {
      console.log('🐘 PostgreSQL already connected');
      return;
    }

    try {
      const connectionString = getDatabaseConnectionString();
      
      this.pool = new Pool({
        connectionString,
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      });

      // Test the connection
      const client = await this.pool.connect();
      await client.query('SELECT NOW()');
      client.release();

      console.log('🐘 PostgreSQL connected successfully');

      // Handle pool events
      this.pool.on('error', (error) => {
        console.error('❌ PostgreSQL pool error:', error);
      });

    } catch (error) {
      console.error('❌ PostgreSQL connection failed:', error);
      throw error;
    }
  }

  public async disconnect(): Promise<void> {
    if (!this.pool) {
      return;
    }

    try {
      await this.pool.end();
      this.pool = null;
      console.log('🐘 PostgreSQL disconnected gracefully');
    } catch (error) {
      console.error('❌ Error disconnecting from PostgreSQL:', error);
      throw error;
    }
  }

  public getPool(): Pool {
    if (!this.pool) {
      throw new Error('PostgreSQL pool not initialized. Call connect() first.');
    }
    return this.pool;
  }

  public async isHealthy(): Promise<boolean> {
    if (!this.pool) {
      return false;
    }

    try {
      const client = await this.pool.connect();
      await client.query('SELECT 1');
      client.release();
      return true;
    } catch {
      return false;
    }
  }
}

// Prisma client (alternative to raw pg)
class PrismaConnection {
  private static instance: PrismaConnection;
  private prisma: PrismaClient | null = null;

  private constructor() {}

  public static getInstance(): PrismaConnection {
    if (!PrismaConnection.instance) {
      PrismaConnection.instance = new PrismaConnection();
    }
    return PrismaConnection.instance;
  }

  public async connect(): Promise<void> {
    if (this.prisma) {
      console.log('🔷 Prisma already connected');
      return;
    }

    try {
      this.prisma = new PrismaClient({
        log: config.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['error'],
      });

      await this.prisma.$connect();
      console.log('🔷 Prisma connected successfully');
    } catch (error) {
      console.error('❌ Prisma connection failed:', error);
      throw error;
    }
  }

  public async disconnect(): Promise<void> {
    if (!this.prisma) {
      return;
    }

    try {
      await this.prisma.$disconnect();
      this.prisma = null;
      console.log('🔷 Prisma disconnected gracefully');
    } catch (error) {
      console.error('❌ Error disconnecting from Prisma:', error);
      throw error;
    }
  }

  public getClient(): PrismaClient {
    if (!this.prisma) {
      throw new Error('Prisma client not initialized. Call connect() first.');
    }
    return this.prisma;
  }

  public async isHealthy(): Promise<boolean> {
    if (!this.prisma) {
      return false;
    }

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return true;
    } catch {
      return false;
    }
  }
}

// Main database connection function
export async function connectDatabase(): Promise<void> {
  switch (config.DATABASE_TYPE) {
    case 'mongodb':
      await MongoDBConnection.getInstance().connect();
      break;
    case 'postgresql':
      // You can choose between raw pg or Prisma
      // For raw PostgreSQL with pg:
      await PostgreSQLConnection.getInstance().connect();
      
      // Or for Prisma (comment out the line above and uncomment below):
      // await PrismaConnection.getInstance().connect();
      break;
    default:
      throw new Error(`Unsupported database type: ${config.DATABASE_TYPE}`);
  }
}

export async function disconnectDatabase(): Promise<void> {
  switch (config.DATABASE_TYPE) {
    case 'mongodb':
      await MongoDBConnection.getInstance().disconnect();
      break;
    case 'postgresql':
      await PostgreSQLConnection.getInstance().disconnect();
      // Or if using Prisma:
      // await PrismaConnection.getInstance().disconnect();
      break;
  }
}

export async function isDatabaseHealthy(): Promise<boolean> {
  switch (config.DATABASE_TYPE) {
    case 'mongodb':
      return MongoDBConnection.getInstance().isHealthy();
    case 'postgresql':
      return await PostgreSQLConnection.getInstance().isHealthy();
      // Or if using Prisma:
      // return await PrismaConnection.getInstance().isHealthy();
    default:
      return false;
  }
}

// Export individual connection instances for direct access
export const mongoConnection = MongoDBConnection.getInstance();
export const pgConnection = PostgreSQLConnection.getInstance();
export const prismaConnection = PrismaConnection.getInstance();