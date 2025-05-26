# Node.js Express TypeScript Starter

A production-ready, modular backend starter template built with Node.js, Express, and TypeScript. This template provides a solid foundation for building scalable REST APIs with best practices, comprehensive error handling, and flexible database support.

## 🚀 Features

- **TypeScript**: Full TypeScript support with strict configuration
- **Express.js**: Fast, unopinionated web framework
- **Database Support**: MongoDB (Mongoose) and PostgreSQL (pg/Prisma)
- **Security**: Helmet, CORS, rate limiting, and request validation
- **Error Handling**: Centralized error handling with custom error classes
- **Logging**: Request logging and error tracking
- **Health Checks**: Comprehensive health check endpoints
- **Environment Configuration**: Robust environment variable validation with Zod
- **Production Ready**: Compression, security headers, graceful shutdown
- **Development Tools**: Hot reload, linting, testing setup

## 📁 Project Structure

```
project-root/
├── src/
│   ├── app.ts                 # Express app configuration
│   ├── index.ts              # Server entry point
│   ├── config/
│   │   ├── environment.ts    # Environment validation
│   │   └── db.ts            # Database connections
│   ├── middleware/
│   │   ├── errorHandler.ts  # Error handling middleware
│   │   └── requestLogger.ts # Request logging
│   └── routes/
│       ├── index.ts         # Route aggregation
│       ├── health.ts        # Health check routes
│       └── users.ts         # Example user routes
├── .env.example              # Environment variables template
├── .gitignore               # Git ignore rules
├── package.json             # Dependencies and scripts
├── tsconfig.json            # TypeScript configuration
└── README.md                # Project documentation
```

## 🛠️ Installation

1. **Clone or download the template**

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Database setup**
   
   **For MongoDB:**
   ```bash
   # Install MongoDB locally or use MongoDB Atlas
   # Update MONGODB_URI in .env
   ```

   **For PostgreSQL:**
   ```bash
   # Install PostgreSQL locally or use a cloud service
   # Update PostgreSQL configuration in .env
   ```

## 🚦 Getting Started

### Development
```bash
npm run dev
```

### Production Build
```bash
npm run build
npm start
```

### Available Scripts
- `npm run dev` - Start development server with hot reload
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Start production server
- `npm run clean` - Clean build directory
- `npm run type-check` - Check TypeScript without building
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint errors
- `npm test` - Run tests
- `npm run test:watch` - Run tests in watch mode
- `npm run test:coverage` - Run tests with coverage

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Server
NODE_ENV=development
PORT=3000

# Database
DATABASE_TYPE=mongodb  # or postgresql
MONGODB_URI=mongodb://localhost:27017/your-db

# Security
JWT_SECRET=your-secret-key
CORS_ORIGIN=http://localhost:3000
```

### Database Configuration

The template supports both MongoDB and PostgreSQL:

**MongoDB with Mongoose:**
```typescript
// Set in .env
DATABASE_TYPE=mongodb
MONGODB_URI=mongodb://localhost:27017/your-database
```

**PostgreSQL with pg:**
```typescript
// Set in .env
DATABASE_TYPE=postgresql
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=username
POSTGRES_PASSWORD=password
POSTGRES_DATABASE=database_name
```

**PostgreSQL with Prisma:**
```typescript
// Uncomment Prisma connection in src/config/db.ts
// Set in .env
DATABASE_TYPE=postgresql
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
```

## 📊 Health Checks

The template includes comprehensive health check endpoints:

- `GET /health` - Basic health status
- `GET /api/health` - Detailed health information
- `GET /api/health/ready` - Readiness probe (for Kubernetes)
- `GET /api/health/live` - Liveness probe (for Kubernetes)

## 🛡️ Security Features

- **Helmet**: Security headers
- **CORS**: Cross-origin resource sharing
- **Rate Limiting**: Request rate limiting
- **Input Validation**: Request validation middleware
- **Error Handling**: Secure error responses

## 🔍 API Examples

### Users API

```bash
# Get all users
GET /api/users

# Get user by ID
GET /api/users/:id

# Create user
POST /api/users
{
  "name": "John Doe",
  "email": "john@example.com"
}

# Update user
PUT /api/users/:id
{
  "name": "Jane Doe"
}

# Delete user
DELETE /api/users/:id
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## 🚀 Deployment

### Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

### Environment Setup
1. Set `NODE_ENV=production`
2. Configure production database
3. Set secure `JWT_SECRET`
4. Configure appropriate `CORS_ORIGIN`

## 🏗️ Architecture Decisions

### Modular Design
- **Separation of Concerns**: Each module has a single responsibility
- **Dependency Injection**: Easy to test and swap implementations
- **Configuration Management**: Centralized environment handling

### Error Handling
- **Custom Error Classes**: Structured error responses
- **Async Error Handling**: Proper async/await error catching
- **Logging**: Comprehensive error logging

### Database Abstraction
- **Multiple Database Support**: Easy to switch between databases
- **Connection Management**: Proper connection pooling and cleanup
- **Health Monitoring**: Database health checks

## 📚 Adding New Features

### Adding a New Route
1. Create route file in `src/routes/`
2. Import and register in `src/routes/index.ts`
3. Add middleware if needed

### Adding Database Models
1. Create model files in `src/models/`
2. Import in route handlers
3. Add migrations if using PostgreSQL

### Adding Middleware
1. Create middleware in `src/middleware/`
2. Register in `src/app.ts` or specific routes

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Express.js team for the excellent framework
- TypeScript team for type safety
- All the open-source contributors who made this possible