import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { config } from '../src/config/environment';

let mongod: MongoMemoryServer;

beforeAll(async () => {
  // Start in-memory MongoDB
  mongod = await MongoMemoryServer.create();
  const uri = mongod.getUri();
  
  // Override MongoDB URI for tests
  config.MONGODB_URI = uri;
  config.NODE_ENV = 'test';
  
  // Connect to the in-memory database
  await mongoose.connect(uri);
});

beforeEach(async () => {
  // Clean all collections before each test
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    const collection = collections[key];
    if (collection) {
      await collection.deleteMany({});
    }
  }
});

afterAll(async () => {
  // Close database connection
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
    
  // Stop the in-memory MongoDB instance
  if (mongod) {
    await mongod.stop();
  }
});