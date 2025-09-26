# AuthFlow API

A production-ready authentication API built with Node.js, Express, TypeScript, and MongoDB. Features comprehensive user management, JWT-based authentication, OAuth integration, and robust security measures.

**🚀 Live API:** [authflow.kuldeepdev.me](https://authflow.kuldeepdev.me)  
**📚 API Documentation:** [authflow-docs.kuldeepdev.me](https://authflow-docs.kuldeepdev.me)

## Features

- **JWT Authentication** - Access tokens with refresh token rotation
- **User Management** - Registration, login, profile management
- **Email Verification** - OTP-based email verification system
- **Password Recovery** - Secure password reset with email notifications
- **OAuth Integration** - Google OAuth2.0 support
- **Admin Panel** - User management and administrative controls  
- **Security** - Rate limiting, CORS, helmet, input validation
- **Health Monitoring** - Comprehensive system health checks
- **TypeScript** - Full type safety and modern development
- **Testing** - Jest test suite with authentication coverage
- **Interactive Documentation** - Complete API docs with testing interface

## Tech Stack

- **Runtime:** Node.js 18+
- **Framework:** Express.js
- **Language:** TypeScript
- **Database:** MongoDB with Mongoose ODM
- **Authentication:** JWT + Refresh Tokens
- **Email:** Nodemailer with Gmail SMTP
- **Validation:** Zod schema validation
- **Testing:** Jest with Supertest
- **Security:** Helmet, CORS, bcryptjs, rate limiting

## Quick Start

### Prerequisites

- Node.js 18+ 
- MongoDB 4.4+
- Gmail account for email services

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd authflow-api

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration (see Environment Setup below)

# Start development server
npm run dev
```

### Environment Setup

Create a `.env` file with the following configuration:

```bash
# Server Configuration
NODE_ENV=development
PORT=3000

# Database
DATABASE_TYPE=mongodb
MONGODB_URI=mongodb://localhost:27017/authflow
MONGODB_URI_TEST=mongodb://localhost:27017/authflow-test

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d
BCRYPT_ROUNDS=12

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-app-specific-password
EMAIL_FROM=your-gmail@gmail.com
EMAIL_SECURE=false
EMAIL_SERVICE=gmail

# OAuth (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Application
APP_NAME=AuthFlow API
CLIENT_URL=http://localhost:3000
CORS_ORIGIN=http://localhost:3000
```

### Available Scripts

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build TypeScript to JavaScript
npm start            # Start production server
npm run clean        # Clean build directory
npm run type-check   # TypeScript type checking
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint errors
npm test             # Run test suite
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
```

## Project Structure

```
src/
├── app.ts                    # Express app configuration
├── index.ts                  # Server entry point
├── config/
│   ├── db.ts                # Database connection
│   ├── environment.ts       # Environment validation
│   └── passport.ts          # OAuth configuration
├── controllers/
│   ├── adminController.ts   # Admin user management
│   ├── authController.ts    # Authentication logic
│   └── userController.ts    # User profile management
├── middleware/
│   ├── authMiddleware.ts    # JWT validation
│   ├── errorHandler.ts      # Error handling
│   ├── requestLogger.ts     # Request logging
│   └── validationMiddleware.ts # Input validation
├── models/
│   ├── blacklistedTokenModel.ts # Token blacklist
│   └── userModel.ts         # User schema
├── routes/
│   ├── adminRoutes.ts       # Admin endpoints
│   ├── authRoutes.ts        # Auth endpoints
│   ├── health.ts            # Health checks
│   ├── index.ts             # Route aggregation
│   └── userRoutes.ts        # User endpoints
├── services/
│   └── emailService.ts      # Email functionality
├── types/
│   └── userTypes.ts         # TypeScript definitions
├── utils/
│   ├── apiResponse.ts       # Response formatting
│   └── logger.ts            # Logging utilities
└── validators/
    └── userValidator.ts     # Input validation schemas
```

## API Documentation

**📚 Complete API Reference:** [authflow-docs.kuldeepdev.me](https://authflow-docs.kuldeepdev.me)

The interactive documentation includes:
- **All Endpoints** - Complete API reference with examples
- **Interactive Testing** - Test API calls directly from the browser
- **Authentication Guide** - JWT implementation details
- **Request/Response Examples** - Real JSON examples for every endpoint
- **Error Handling** - Complete error codes and responses
- **Rate Limiting** - Usage limits and best practices

### Quick API Overview

#### Health Checks
- `GET /health` - Basic health status
- `GET /api/health` - Detailed system health
- `GET /api/health/ready` - Readiness probe
- `GET /api/health/live` - Liveness probe

#### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login  
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh-token` - Refresh access token
- `POST /api/auth/verify-email` - Verify email with OTP
- `POST /api/auth/resend-verification` - Resend verification email
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `GET /api/auth/google` - Google OAuth login
- `GET /api/auth/google/callback` - Google OAuth callback

#### User Management  
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `PUT /api/users/change-password` - Change password

#### Admin (Admin Role Required)
- `GET /api/admin` - Get all users
- `GET /api/admin/:id` - Get user by ID
- `PUT /api/admin/:id` - Update user
- `DELETE /api/admin/:id` - Delete user

> 💡 **Tip:** Visit the [interactive documentation](https://authflow-docs.kuldeepdev.me) to test these endpoints directly!

## Authentication Flow

### Registration Process
1. User submits registration details
2. Server validates input and creates user account
3. Verification email sent with 6-digit OTP
4. User verifies email with OTP
5. Account activated and JWT tokens issued

### Login Process  
1. User submits email/password
2. Server validates credentials
3. JWT access token (24h) + refresh token (7d) issued
4. Client stores tokens securely

### Token Refresh
1. When access token expires, use refresh token
2. Server validates refresh token
3. New access token issued
4. Refresh token rotated for security

## Security Features

- **Password Security** - bcrypt hashing with 12 rounds
- **JWT Security** - Short-lived access tokens with refresh rotation  
- **Rate Limiting** - 100 requests per 15 minutes per IP
- **Input Validation** - Zod schema validation on all endpoints
- **CORS Protection** - Configurable origin whitelist
- **Security Headers** - Helmet.js for HTTP security
- **Token Blacklisting** - Logout invalidates tokens immediately
- **Email Verification** - Prevents unverified account access

## Error Handling

The API uses consistent error responses:

```json
{
  "success": false,
  "error": {
    "message": "User-friendly error message",
    "code": "ERROR_CODE",
    "statusCode": 400,
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

Common error codes:
- `VALIDATION_ERROR` - Input validation failed
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMITED` - Too many requests
- `SERVER_ERROR` - Internal server error

## Development

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode  
npm run test:watch

# Generate coverage report
npm run test:coverage
```

### Code Quality

```bash
# Type checking
npm run type-check

# Linting
npm run lint
npm run lint:fix
```

### Health Checks

The API includes comprehensive health monitoring:

- **Basic Health:** `GET /health` - Simple OK/ERROR status
- **Detailed Health:** `GET /api/health` - System metrics and database status
- **Kubernetes Probes:** `/api/health/ready` and `/api/health/live`

Health check responses include:
- Database connectivity status
- Memory usage statistics  
- System uptime
- Environment information

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow TypeScript strict mode
- Write tests for new functionality
- Update documentation for API changes
- Use conventional commit messages
- Ensure all tests pass before submitting

## Performance & Monitoring

- **Request Logging** - Morgan + custom request logger
- **Error Tracking** - Comprehensive error logging
- **Performance Metrics** - Response time monitoring
- **Database Optimization** - Proper indexing on frequently queried fields
- **Memory Management** - Graceful shutdown and cleanup

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support & Resources

### Documentation & Testing
- **🚀 Live API:** [authflow.kuldeepdev.me](https://authflow.kuldeepdev.me)
- **📚 Interactive Documentation:** [authflow-docs.kuldeepdev.me](https://authflow-docs.kuldeepdev.me)
- **💚 Health Status:** [authflow.kuldeepdev.me/health](https://authflow.kuldeepdev.me/health)

### Getting Help
- **Issues:** Open an issue in the repository for bugs or feature requests
- **Questions:** Check the [API documentation](https://authflow-docs.kuldeepdev.me) first
- **Contact:** For direct support and inquiries

### Quick Links
- [Register a new account](https://authflow-docs.kuldeepdev.me#/Authentication/post_api_auth_register) 
- [Login endpoint](https://authflow-docs.kuldeepdev.me#/Authentication/post_api_auth_login)
- [API health status](https://authflow.kuldeepdev.me/health)

---

