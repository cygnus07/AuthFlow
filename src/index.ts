import 'dotenv/config';
import App from './app';
import { connectDatabase } from '@/config/db';
// import { config } from '@/config/environment';

class Server {
  private app: App;

  constructor() {
    this.app = new App();
  }

  public async start(): Promise<void> {
    try {
      // Initialize database connection
      await this.initializeDatabase();
      
      // Start the server
      this.app.listen();
      
      // Graceful shutdown handlers
      this.setupGracefulShutdown();
      
    } catch (error) {
      console.error('❌ Failed to start server:', error);
      process.exit(1);
    }
  }

  private async initializeDatabase(): Promise<void> {
    try {
      await connectDatabase();
      console.log('✅ Database connected successfully');
    } catch (error) {
      console.error('❌ Database connection failed:', error);
      throw error;
    }
  }

  private setupGracefulShutdown(): void {
    const shutdown = (signal: string) => {
      console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
      
      // Close database connections
      // Add any cleanup logic here
      
      process.exit(0);
    };

    // Handle different shutdown signals
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      console.error('🚨 Uncaught Exception:', error);
      process.exit(1);
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: unknown, promise: Promise<any>) => {
      console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
      process.exit(1);
    });
  }
}

// Start the server
const server = new Server();
server.start().catch((error) => {
  console.error('❌ Server startup failed:', error);
  process.exit(1);
});