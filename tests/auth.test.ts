import request from 'supertest';
import App from '../src/app';
import User from '../src/models/userModel';
import BlacklistedToken from '../src/models/blacklistedTokenModel';
import { registerSchema } from '../src/validators/userValidator';
import { connectDatabase, disconnectDatabase } from '../src/config/db';
import { emailService } from '../src/services/emailService';
import crypto from 'crypto';
// import jwt from 'jsonwebtoken';
// import { config } from '../src/config/environment';
import { UserRole, AccountStatus } from '../src/types/userTypes';

// Mock the email service
jest.mock('../src/services/emailService', () => ({
  emailService: {
    sendVerificationEmail: jest.fn().mockResolvedValue(true),
    sendWelcomeEmail: jest.fn().mockResolvedValue(true),
    sendPasswordResetEmail: jest.fn().mockResolvedValue(true),
    sendPasswordChangeNotification: jest.fn().mockResolvedValue(true),
  }
}));

// Mock logger to avoid console spam during tests
jest.mock('../src/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    auth: jest.fn(),
    security: jest.fn(),
    database: jest.fn(),
    email: jest.fn(),
    performance: jest.fn(),
  }
}));

describe('Auth Endpoints', () => {
  let app: App;
  let server: any;
  let testUser: any;
  let authToken: string;
  let refreshToken: string;

  beforeAll(async () => {
    await connectDatabase();
    app = new App();
    server = app.app;
    await User.deleteMany({}); // Clear users before tests
    await BlacklistedToken.deleteMany({}); // Clear blacklisted tokens
  });

  afterAll(async () => {
    await User.deleteMany({});
    await BlacklistedToken.deleteMany({});
    await disconnectDatabase();
  });

  beforeEach(() => {
    // Clear email service mocks before each test
    jest.clearAllMocks();
  });

  describe('POST /api/users/register', () => {
    const baseUserData = {
      firstName: 'Test',
      lastName: 'User',
      email: 'test@example.com',
      password: 'ValidPassword123!',
      confirmPassword: 'ValidPassword123!'
    };

    afterEach(async () => {
      // Clean up test users after each test
      await User.deleteMany({ email: baseUserData.email });
    });

    it('should register a new user successfully with valid data', async () => {
      const response = await request(server)
        .post('/api/users/register')
        .send(baseUserData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(baseUserData.email);
      expect(response.body.data.user.firstName).toBe(baseUserData.firstName);
      expect(response.body.data.user.lastName).toBe(baseUserData.lastName);
      expect(response.body.data.user.password).toBeUndefined();
      expect(response.body.data.user.emailVerificationToken).toBeUndefined();
      expect(response.body.message).toContain('Registration successful');

      // Verify user was created in database
      const user = await User.findOne({ email: baseUserData.email });
      expect(user).toBeTruthy();
      expect(user?.emailVerified).toBe(false);
      expect(user?.status).toBe(AccountStatus.PENDING);
      expect(user?.role).toBe(UserRole.USER);

      // Verify email service was called
      expect(emailService.sendVerificationEmail).toHaveBeenCalledWith(
        baseUserData.email,
        baseUserData.firstName,
        expect.any(String)
      );
    }, 10000);

    it('should register user with username', async () => {
      const userDataWithUsername = {
        ...baseUserData,
        email: 'testuser@example.com',
        username: 'testuser123'
      };

      const response = await request(server)
        .post('/api/users/register')
        .send(userDataWithUsername)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.username).toBe(userDataWithUsername.username);

      // Clean up
      await User.deleteMany({ email: userDataWithUsername.email });
    });

    it.each([
      ['missing firstName', { ...baseUserData, firstName: undefined }],
      ['short firstName', { ...baseUserData, firstName: 'A' }],
      ['missing email', { ...baseUserData, email: undefined }],
      ['invalid email', { ...baseUserData, email: 'invalid-email' }],
      ['missing password', { ...baseUserData, password: undefined }],
      ['short password', { ...baseUserData, password: 'short' }],
      ['weak password (no uppercase)', { ...baseUserData, password: 'weakpassword1!' }],
      ['weak password (no number)', { ...baseUserData, password: 'WeakPassword!' }],
      ['weak password (no lowercase)', { ...baseUserData, password: 'WEAKPASSWORD1!' }],
      ['mismatched passwords', { ...baseUserData, confirmPassword: 'Different123!' }],
      ['invalid username format', { ...baseUserData, username: 'invalid username!' }],
      ['short username', { ...baseUserData, username: 'ab' }],
      ['long username', { ...baseUserData, username: 'a'.repeat(31) }],
    ])('should reject registration with %s', async (_description, invalidData) => {
      const response = await request(server)
        .post('/api/users/register')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      
      // Verify the error matches Zod validation
      const validation = registerSchema.safeParse(invalidData);
      expect(validation.success).toBe(false);
    });

    it('should reject duplicate email', async () => {
      // First registration
      await request(server)
        .post('/api/users/register')
        .send(baseUserData)
        .expect(201);

      // Second registration with same email
      const response = await request(server)
        .post('/api/users/register')
        .send({
          ...baseUserData,
          firstName: 'Another',
          lastName: 'User'
        })
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already');
    });

    it('should reject duplicate username', async () => {
      const userData1 = {
        ...baseUserData,
        email: 'user1@example.com',
        username: 'duplicateuser'
      };

      const userData2 = {
        ...baseUserData,
        email: 'user2@example.com',
        username: 'duplicateuser',
        firstName: 'Another',
        lastName: 'User'
      };

      // First registration
      await request(server)
        .post('/api/users/register')
        .send(userData1)
        .expect(201);

      // Second registration with same username
      const response = await request(server)
        .post('/api/users/register')
        .send(userData2)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already taken');

      // Clean up
      await User.deleteMany({ email: { $in: [userData1.email, userData2.email] } });
    });
  });

  describe('POST /api/users/verify-email', () => {
    const verificationData = {
      email: 'verify@example.com',
      password: 'ValidPassword123!'
    };

    let verificationOtp: string;
    let unverifiedUser: any;

    beforeEach(async () => {
      // Create unverified user for each test
      await request(server)
        .post('/api/users/register')
        .send({
          ...verificationData,
          firstName: 'Verify',
          lastName: 'Test',
          confirmPassword: verificationData.password
        });

      unverifiedUser = await User.findOne({ email: verificationData.email });
      
      // Generate OTP that matches the stored hash
      verificationOtp = '123456';
      const hashedOtp = crypto.createHash('sha256').update(verificationOtp).digest('hex');
      unverifiedUser.emailVerificationToken = hashedOtp;
      unverifiedUser.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);
      await unverifiedUser.save();
    });

    afterEach(async () => {
      await User.deleteMany({ email: verificationData.email });
    });

    it('should verify email with valid OTP', async () => {
      const response = await request(server)
        .post('/api/users/verify-email')
        .send({
          email: verificationData.email,
          otp: verificationOtp
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();

      // Verify user is now verified and active
      const user = await User.findOne({ email: verificationData.email });
      expect(user?.emailVerified).toBe(true);
      expect(user?.status).toBe(AccountStatus.ACTIVE);
      expect(user?.emailVerificationToken).toBeUndefined();

      // Verify welcome email was sent
      expect(emailService.sendWelcomeEmail).toHaveBeenCalledWith(
        verificationData.email,
        'Verify'
      );
    });

    it('should reject verification with invalid OTP', async () => {
      const response = await request(server)
        .post('/api/users/verify-email')
        .send({
          email: verificationData.email,
          otp: '000000'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');

      // Verify user is still unverified
      const user = await User.findOne({ email: verificationData.email });
      expect(user?.emailVerified).toBe(false);
    });

    it('should reject verification with expired OTP', async () => {
      // Set expiration to past
      unverifiedUser.passwordResetExpires = new Date(Date.now() - 1000);
      await unverifiedUser.save();

      const response = await request(server)
        .post('/api/users/verify-email')
        .send({
          email: verificationData.email,
          otp: verificationOtp
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('expired');
    });

    it('should reject verification with missing fields', async () => {
      const response = await request(server)
        .post('/api/users/verify-email')
        .send({
          email: verificationData.email
          // missing otp
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/resend-verification', () => {
    const userData = {
      email: 'resend@example.com',
      password: 'ValidPassword123!'
    };

    beforeEach(async () => {
      // Create unverified user
      await request(server)
        .post('/api/users/register')
        .send({
          ...userData,
          firstName: 'Resend',
          lastName: 'Test',
          confirmPassword: userData.password
        });
    });

    afterEach(async () => {
      await User.deleteMany({ email: userData.email });
    });

    it('should resend verification email for unverified user', async () => {
      const response = await request(server)
        .post('/api/users/resend-verification')
        .send({ email: userData.email })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('sent successfully');

      // Verify email service was called again
      expect(emailService.sendVerificationEmail).toHaveBeenCalledTimes(2); // Once during registration, once during resend
    });

    it('should reject resend for non-existent email', async () => {
      const response = await request(server)
        .post('/api/users/resend-verification')
        .send({ email: 'nonexistent@example.com' })
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject resend for already verified user', async () => {
      // Verify the user first
      const user = await User.findOne({ email: userData.email });
      user!.emailVerified = true;
      user!.status = AccountStatus.ACTIVE;
      await user!.save();

      const response = await request(server)
        .post('/api/users/resend-verification')
        .send({ email: userData.email })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/login', () => {
    const loginData = {
      email: 'login@example.com',
      password: 'ValidPassword123!'
    };

    beforeAll(async () => {
      // Create a verified user for login tests
      await request(server)
        .post('/api/users/register')
        .send({
          ...loginData,
          firstName: 'Login',
          lastName: 'Test',
          confirmPassword: loginData.password
        });

      testUser = await User.findOne({ email: loginData.email });
      testUser.emailVerified = true;
      testUser.status = AccountStatus.ACTIVE;
      await testUser.save();
    });

    afterAll(async () => {
      await User.deleteMany({ email: loginData.email });
    });

    it('should login with valid credentials', async () => {
      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.user).toBeDefined();
      expect(response.body.data.user.password).toBeUndefined();
      
      authToken = response.body.data.token;
      refreshToken = response.body.data.refreshToken;

      // Verify response structure matches your controller
      expect(response.body.message).toBe('Login successful');

      // Verify last login was updated
      const user = await User.findOne({ email: loginData.email });
      expect(user?.lastLogin).toBeTruthy();
    });

    it.each([
      ['missing email', { password: loginData.password }],
      ['invalid email', { email: 'invalid-email', password: loginData.password }],
      ['missing password', { email: loginData.email }],
      ['incorrect password', { email: loginData.email, password: 'wrong-password' }],
    ])('should reject login with %s', async (_description, invalidData) => {
      const expectedStatus = _description === 'incorrect password' ? 401 : 400;
      
      const response = await request(server)
        .post('/api/users/login')
        .send(invalidData)
        .expect(expectedStatus);

      expect(response.body.success).toBe(false);
    });

    it('should reject login for unverified email', async () => {
      // Create unverified user
      const unverifiedData = {
        email: 'unverified@example.com',
        password: 'ValidPassword123!',
        firstName: 'Unverified',
        lastName: 'User',
        confirmPassword: 'ValidPassword123!'
      };

      await request(server)
        .post('/api/users/register')
        .send(unverifiedData);

      const response = await request(server)
        .post('/api/users/login')
        .send({
          email: unverifiedData.email,
          password: unverifiedData.password
        })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('verified');

      // Clean up
      await User.deleteMany({ email: unverifiedData.email });
    });

    it('should reject login for inactive user', async () => {
      // Create inactive user
      const inactiveData = {
        email: 'inactive@example.com',
        password: 'ValidPassword123!',
        firstName: 'Inactive',
        lastName: 'User',
        confirmPassword: 'ValidPassword123!'
      };

      await request(server)
        .post('/api/users/register')
        .send(inactiveData);

      const user = await User.findOne({ email: inactiveData.email });
      user!.emailVerified = true;
      user!.status = AccountStatus.SUSPENDED;
      await user!.save();

      const response = await request(server)
        .post('/api/users/login')
        .send({
          email: inactiveData.email,
          password: inactiveData.password
        })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('suspended');

      // Clean up
      await User.deleteMany({ email: inactiveData.email });
    });

    it('should reject login for non-existent user', async () => {
      const response = await request(server)
        .post('/api/users/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'ValidPassword123!'
        })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid credentials');
    });
  });

  describe('POST /api/users/forgot-password', () => {
    const userData = {
      email: 'forgot@example.com',
      password: 'ValidPassword123!'
    };

    beforeAll(async () => {
      // Create verified user for password reset
      await request(server)
        .post('/api/users/register')
        .send({
          ...userData,
          firstName: 'Forgot',
          lastName: 'Test',
          confirmPassword: userData.password
        });

      const user = await User.findOne({ email: userData.email });
      user!.emailVerified = true;
      user!.status = AccountStatus.ACTIVE;
      await user!.save();
    });

    afterAll(async () => {
      await User.deleteMany({ email: userData.email });
    });

    it('should send password reset email for existing user', async () => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send({ email: userData.email })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('password reset link');

      // Verify email service was called
      expect(emailService.sendPasswordResetEmail).toHaveBeenCalledWith(
        userData.email,
        'Forgot',
        expect.any(String)
      );

      // Verify reset token was set
      const user = await User.findOne({ email: userData.email });
      expect(user?.passwordResetToken).toBeTruthy();
      expect(user?.passwordResetExpires).toBeTruthy();
    });

    it('should return success for non-existent email (security)', async () => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send({ email: 'nonexistent@example.com' })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('If a user with that email exists');

      // Verify email service was not called
      expect(emailService.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('should reject request with missing email', async () => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject request with invalid email', async () => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send({ email: 'invalid-email' })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/reset-password', () => {
    const userData = {
      email: 'reset@example.com',
      password: 'ValidPassword123!'
    };

    let resetToken: string;
    let hashedToken: string;

    beforeEach(async () => {
      // Create user and set reset token
      await request(server)
        .post('/api/users/register')
        .send({
          ...userData,
          firstName: 'Reset',
          lastName: 'Test',
          confirmPassword: userData.password
        });

      resetToken = crypto.randomBytes(32).toString('hex');
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

      const user = await User.findOne({ email: userData.email });
      user!.emailVerified = true;
      user!.status = AccountStatus.ACTIVE;
      user!.passwordResetToken = hashedToken;
      user!.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await user!.save();
    });

    afterEach(async () => {
      await User.deleteMany({ email: userData.email });
    });

    it('should reset password with valid token', async () => {
      const newPassword = 'NewValidPassword123!';
      
      const response = await request(server)
        .post('/api/users/reset-password')
        .send({
          token: resetToken,
          password: newPassword,
          confirmPassword: newPassword
        })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('reset successfully');

      // Verify password was changed
      const user = await User.findOne({ email: userData.email }).select('+password');
      expect(user?.passwordResetToken).toBeUndefined();
      expect(user?.passwordResetExpires).toBeUndefined();
      expect(user?.passwordChangedAt).toBeTruthy();

      // Verify password change notification was sent
      expect(emailService.sendPasswordChangeNotification).toHaveBeenCalledWith(
        userData.email,
        'Reset'
      );

      // Verify old password doesn't work
      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({
          email: userData.email,
          password: userData.password
        })
        .expect(401);

      expect(loginResponse.body.success).toBe(false);
    });

    it.each([
      ['missing token', { password: 'NewValidPassword123!', confirmPassword: 'NewValidPassword123!' }],
      ['missing password', { token: 'some-token', confirmPassword: 'NewValidPassword123!' }],
      ['missing confirm password', { token: 'some-token', password: 'NewValidPassword123!' }],
      ['weak password', { token: 'some-token', password: 'weak', confirmPassword: 'weak' }],
      ['mismatched passwords', { token: 'some-token', password: 'NewValidPassword123!', confirmPassword: 'Different123!' }],
    ])('should reject password reset with %s', async (_description, invalidData) => {
      const response = await request(server)
        .post('/api/users/reset-password')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject password reset with invalid token', async () => {
      const response = await request(server)
        .post('/api/users/reset-password')
        .send({
          token: 'invalid-token',
          password: 'NewValidPassword123!',
          confirmPassword: 'NewValidPassword123!'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('invalid');
    });

    it('should reject password reset with expired token', async () => {
      // Set token expiration to past
      const user = await User.findOne({ email: userData.email });
      user!.passwordResetExpires = new Date(Date.now() - 1000);
      await user!.save();

      const response = await request(server)
        .post('/api/users/reset-password')
        .send({
          token: resetToken,
          password: 'NewValidPassword123!',
          confirmPassword: 'NewValidPassword123!'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('expired');
    });
  });

  describe('POST /api/users/refresh-token', () => {
    beforeAll(async () => {
      // Ensure we have valid tokens
      if (!refreshToken) {
        const loginResponse = await request(server)
          .post('/api/users/login')
          .send({
            email: 'login@example.com',
            password: 'ValidPassword123!'
          });
        refreshToken = loginResponse.body.data.refreshToken;
      }
    });

    it('should refresh token with valid refresh token', async () => {
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.message).toBe('Token refreshed successfully');

      // Verify new token is different from old one
      expect(response.body.data.token).not.toBe(authToken);
    });

    it('should reject refresh with missing token', async () => {
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject refresh with invalid token', async () => {
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');
    });

    it('should reject refresh with blacklisted token', async () => {
      // First, logout to blacklist the token
      await request(server)
        .post('/api/users/logout')
        .send({ refreshToken })
        .expect(200);

      // Then try to use the blacklisted token
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send({ refreshToken })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('revoked');
    });
  });

  describe('Protected Routes', () => {
    let validAuthToken: string;

    beforeAll(async () => {
      // Get fresh auth token
      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({
          email: 'login@example.com',
          password: 'ValidPassword123!'
        });
      validAuthToken = loginResponse.body.data.token;
    });

    describe('GET /api/users/profile', () => {
      it('should get user profile with valid token', async () => {
        const response = await request(server)
          .get('/api/users/profile')
          .set('Authorization', `Bearer ${validAuthToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.user).toBeDefined();
        expect(response.body.data.user.email).toBe('login@example.com');
        expect(response.body.data.user.password).toBeUndefined();
      });

      it('should reject profile request without token', async () => {
        const response = await request(server)
          .get('/api/users/profile')
          .expect(401);

        expect(response.body.success).toBe(false);
      });

      it('should reject profile request with invalid token', async () => {
        const response = await request(server)
          .get('/api/users/profile')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401);

        expect(response.body.success).toBe(false);
      });
    });

    describe('PUT /api/users/profile', () => {
      it('should update profile with valid data', async () => {
        const updateData = {
          firstName: 'Updated',
          lastName: 'Name',
          phone: '+1234567890'
        };

        const response = await request(server)
          .put('/api/users/profile')
          .set('Authorization', `Bearer ${validAuthToken}`)
          .send(updateData)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.user.firstName).toBe(updateData.firstName);
        expect(response.body.data.user.lastName).toBe(updateData.lastName);
        expect(response.body.data.user.phone).toBe(updateData.phone);
      });

      it('should reject profile update without authentication', async () => {
        const response = await request(server)
          .put('/api/users/profile')
          .send({ firstName: 'Updated' })
          .expect(401);

        expect(response.body.success).toBe(false);
      });
    });

    describe('PUT /api/users/change-password', () => {
      it('should change password with valid current password', async () => {
        const changePasswordData = {
          currentPassword: 'ValidPassword123!',
          newPassword: 'NewValidPassword123!'
        };

        const response = await request(server)
          .put('/api/users/change-password')
          .set('Authorization', `Bearer ${validAuthToken}`)
          .set('Authorization', `Bearer ${validAuthToken}`)
          .send(changePasswordData)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.message).toContain('changed successfully');

        // Verify password change notification was sent
        expect(emailService.sendPasswordChangeNotification).toHaveBeenCalledWith(
          'login@example.com',
          expect.any(String)
        );

        // Verify old password doesn't work anymore
        const loginResponse = await request(server)
          .post('/api/users/login')
          .send({
            email: 'login@example.com',
            password: 'ValidPassword123!'
          })
          .expect(401);

        expect(loginResponse.body.success).toBe(false);

        // Verify new password works
        const newLoginResponse = await request(server)
          .post('/api/users/login')
          .send({
            email: 'login@example.com',
            password: 'NewValidPassword123!'
          })
          .expect(200);

        expect(newLoginResponse.body.success).toBe(true);
      });

      it('should reject password change with incorrect current password', async () => {
        const response = await request(server)
          .put('/api/users/change-password')
          .set('Authorization', `Bearer ${validAuthToken}`)
          .send({
            currentPassword: 'wrong-password',
            newPassword: 'NewValidPassword123!'
          })
          .expect(401);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('incorrect');
      });

      it('should reject password change with weak new password', async () => {
        const response = await request(server)
          .put('/api/users/change-password')
          .set('Authorization', `Bearer ${validAuthToken}`)
          .send({
            currentPassword: 'ValidPassword123!',
            newPassword: 'weak'
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.message).toContain('strong');
      });

      it('should reject password change without authentication', async () => {
        const response = await request(server)
          .put('/api/users/change-password')
          .send({
            currentPassword: 'ValidPassword123!',
            newPassword: 'NewValidPassword123!'
          })
          .expect(401);

        expect(response.body.success).toBe(false);
      });
    });
  });

  describe('POST /api/users/logout', () => {
    let logoutRefreshToken: string;

    beforeAll(async () => {
      // Get fresh refresh token for logout tests
      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({
          email: 'login@example.com',
          password: 'ValidPassword123!'
        });
      logoutRefreshToken = loginResponse.body.data.refreshToken;
    });

    it('should logout successfully with valid refresh token', async () => {
      const response = await request(server)
        .post('/api/users/logout')
        .send({ refreshToken: logoutRefreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('successful');

      // Verify token was blacklisted
      const blacklistedToken = await BlacklistedToken.findOne({ token: logoutRefreshToken });
      expect(blacklistedToken).toBeTruthy();

      // Verify token can't be used for refresh
      const refreshResponse = await request(server)
        .post('/api/users/refresh-token')
        .send({ refreshToken: logoutRefreshToken })
        .expect(401);

      expect(refreshResponse.body.success).toBe(false);
    });

    it('should reject logout without refresh token', async () => {
      const response = await request(server)
        .post('/api/users/logout')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject logout with invalid refresh token', async () => {
      const response = await request(server)
        .post('/api/users/logout')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Admin Routes', () => {
    let adminToken: string;
    let adminUser: any;
    let regularUser: any;

    beforeAll(async () => {
      // Create admin user
      await request(server)
        .post('/api/users/register')
        .send({
          firstName: 'Admin',
          lastName: 'User',
          email: 'admin@example.com',
          password: 'AdminPassword123!',
          confirmPassword: 'AdminPassword123!',
          role: UserRole.ADMIN
        });

      adminUser = await User.findOne({ email: 'admin@example.com' });
      adminUser!.emailVerified = true;
      adminUser!.status = AccountStatus.ACTIVE;
      await adminUser!.save();

      // Login as admin
      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({
          email: 'admin@example.com',
          password: 'AdminPassword123!'
        });
      adminToken = loginResponse.body.data.token;

      // Create regular user for admin tests
      await request(server)
        .post('/api/users/register')
        .send({
          firstName: 'Regular',
          lastName: 'User',
          email: 'regular@example.com',
          password: 'RegularPassword123!',
          confirmPassword: 'RegularPassword123!'
        });

      regularUser = await User.findOne({ email: 'regular@example.com' });
      regularUser!.emailVerified = true;
      regularUser!.status = AccountStatus.ACTIVE;
      await regularUser!.save();
    });

    afterAll(async () => {
      await User.deleteMany({ email: { $in: ['admin@example.com', 'regular@example.com'] } });
    });

    describe('GET /api/users/admin', () => {
      it('should list users for admin', async () => {
        const response = await request(server)
          .get('/api/users/admin')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.users).toBeInstanceOf(Array);
        expect(response.body.data.pagination).toBeDefined();
        expect(response.body.data.pagination.total).toBeGreaterThanOrEqual(2);
      });

      it('should reject user list for non-admin', async () => {
        // Login as regular user
        const loginResponse = await request(server)
          .post('/api/users/login')
          .send({
            email: 'regular@example.com',
            password: 'RegularPassword123!'
          });
        const regularToken = loginResponse.body.data.token;

        const response = await request(server)
          .get('/api/users/admin')
          .set('Authorization', `Bearer ${regularToken}`)
          .expect(403);

        expect(response.body.success).toBe(false);
      });
    });

    describe('GET /api/users/admin/:id', () => {
      it('should get user by ID for admin', async () => {
        const response = await request(server)
          .get(`/api/users/admin/${regularUser!._id}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.user._id).toBe(regularUser!._id.toString());
      });

      it('should return 404 for non-existent user', async () => {
        const nonExistentId = '507f1f77bcf86cd799439011';
        const response = await request(server)
          .get(`/api/users/admin/${nonExistentId}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(404);

        expect(response.body.success).toBe(false);
      });
    });

    describe('PUT /api/users/admin/:id', () => {
      it('should update user by admin', async () => {
        const updateData = {
          firstName: 'Updated',
          lastName: 'ByAdmin',
          status: AccountStatus.SUSPENDED
        };

        const response = await request(server)
          .put(`/api/users/admin/${regularUser!._id}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .send(updateData)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.data.user.firstName).toBe(updateData.firstName);
        expect(response.body.data.user.lastName).toBe(updateData.lastName);
        expect(response.body.data.user.status).toBe(updateData.status);
      });
    });

    describe('DELETE /api/users/admin/:id', () => {
      it('should delete user by admin', async () => {
        // Create a user to delete
        await request(server)
          .post('/api/users/register')
          .send({
            firstName: 'ToDelete',
            lastName: 'User',
            email: 'todelete@example.com',
            password: 'DeletePassword123!',
            confirmPassword: 'DeletePassword123!'
          });

        const userToDelete = await User.findOne({ email: 'todelete@example.com' });

        const response = await request(server)
          .delete(`/api/users/admin/${userToDelete!._id}`)
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);

        expect(response.body.success).toBe(true);

        // Verify user was deleted
        const deletedUser = await User.findById(userToDelete!._id);
        expect(deletedUser).toBeNull();
      });
    });
  });
});