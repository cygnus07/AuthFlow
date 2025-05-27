import request from 'supertest';
import App from '../src/app';
import User from '../src/models/userModel';
import { registerSchema, loginSchema, changePasswordSchema, resetPasswordSchema } from '../src/validators/userValidator';
import { connectDatabase, disconnectDatabase } from '../src/config/db'
import { UserRole } from '../src/types/userTypes';

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
  });

  afterAll(async () => {
    await User.deleteMany({});
    await disconnectDatabase();
  });

  describe('POST /api/users/register', () => {
    const baseUserData = {
      firstName: 'Test',
      lastName: 'User',
      email: 'test@example.com',
      password: 'ValidPassword123!',
      confirmPassword: 'ValidPassword123!'
    };

    it('should register a new user successfully with valid data', async () => {
      const response = await request(server)
        .post('/api/users/register')
        .send(baseUserData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe(baseUserData.email);
      expect(response.body.data.user.password).toBeUndefined();

      // Verify user was created in database
      const user = await User.findOne({ email: baseUserData.email });
      expect(user).toBeTruthy();
      expect(user?.emailVerified).toBe(false);
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
      ['weak password (no special char)', { ...baseUserData, password: 'WeakPassword1' }],
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
        .send(baseUserData)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already exists');
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
      await testUser.save();
    });

    it('should login with valid credentials', async () => {
      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      
      authToken = response.body.data.accessToken;
      refreshToken = response.body.data.refreshToken;

      // Verify response matches login schema
      const validation = loginSchema.safeParse(loginData);
      expect(validation.success).toBe(true);
    });

    it.each([
  ['missing email', { password: loginData.password }],
  ['invalid email', { email: 'invalid-email', password: loginData.password }],
  ['missing password', { email: loginData.email }],
  ['incorrect password', { email: loginData.email, password: 'wrong-password' }],
])('should reject login with %s', async (description, invalidData) => {
  const response = await request(server)
    .post('/api/users/login')
    .send(invalidData)
    .expect(400);

  expect(response.body.success).toBe(false);
  
  // Verify the error matches Zod validation when applicable
  if ('email' in invalidData && 'password' in invalidData) {
    const validation = loginSchema.safeParse(invalidData);
    expect(validation.success).toBe(
      !!invalidData.email && invalidData.email.includes('@') && !!invalidData.password && invalidData.password.length > 0
    );
  }
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
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('verify');
    });
  });

  describe('POST /api/users/change-password', () => {
    const changePasswordData = {
      currentPassword: 'ValidPassword123!',
      newPassword: 'NewValidPassword123!',
      confirmNewPassword: 'NewValidPassword123!'
    };

    beforeAll(async () => {
      // Ensure we have a logged in user
      if (!authToken) {
        const loginResponse = await request(server)
          .post('/api/users/login')
          .send({
            email: 'login@example.com',
            password: 'ValidPassword123!'
          });
        authToken = loginResponse.body.data.accessToken;
      }
    });

    it('should change password with valid data', async () => {
      const response = await request(server)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${authToken}`)
        .send(changePasswordData)
        .expect(200);

      expect(response.body.success).toBe(true);
      
      // Verify the request matches the schema
      const validation = changePasswordSchema.safeParse(changePasswordData);
      expect(validation.success).toBe(true);
    });

    it.each([
      ['missing current password', { ...changePasswordData, currentPassword: undefined }],
      ['missing new password', { ...changePasswordData, newPassword: undefined }],
      ['weak new password', { ...changePasswordData, newPassword: 'weak' }],
      ['mismatched passwords', { ...changePasswordData, confirmNewPassword: 'Different123!' }],
      ['same as current password', { 
        ...changePasswordData, 
        newPassword: changePasswordData.currentPassword,
        confirmNewPassword: changePasswordData.currentPassword
      }],
    ])('should reject password change with %s', async (description, invalidData) => {
      const response = await request(server)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      
      // Verify the error matches Zod validation
      const validation = changePasswordSchema.safeParse(invalidData);
      expect(validation.success).toBe(false);
    });

    it('should reject password change with incorrect current password', async () => {
      const response = await request(server)
        .post('/api/users/change-password')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          ...changePasswordData,
          currentPassword: 'WrongCurrentPassword!'
        })
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/forgot-password', () => {
    it('should accept valid email for password reset', async () => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send({ email: 'login@example.com' })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it.each([
      ['missing email', {}],
      ['invalid email', { email: 'invalid-email' }],
      ['non-existent email', { email: 'nonexistent@example.com' }],
    ])('should reject password reset with %s', async (description, invalidData) => {
      const response = await request(server)
        .post('/api/users/forgot-password')
        .send(invalidData)
        .expect(description === 'non-existent email' ? 200 : 400);

      expect(response.body.success).toBe(description === 'non-existent email');
    });
  });

  describe('POST /api/users/reset-password', () => {
    const resetData = {
      token: 'valid-reset-token', // In real tests, you'd generate a real token
      newPassword: 'NewValidPassword123!',
      confirmNewPassword: 'NewValidPassword123!'
    };

    it('should reset password with valid token', async () => {
      // Note: In a real test, you'd need to generate a valid reset token first
      const response = await request(server)
        .post('/api/users/reset-password')
        .send(resetData)
        .expect(200);

      expect(response.body.success).toBe(true);
      
      // Verify the request matches the schema
      const validation = resetPasswordSchema.safeParse(resetData);
      expect(validation.success).toBe(true);
    });

    it.each([
      ['missing token', { ...resetData, token: undefined }],
      ['missing new password', { ...resetData, newPassword: undefined }],
      ['weak new password', { ...resetData, newPassword: 'weak' }],
      ['mismatched passwords', { ...resetData, confirmNewPassword: 'Different123!' }],
    ])('should reject password reset with %s', async (description, invalidData) => {
      const response = await request(server)
        .post('/api/users/reset-password')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      
      // Verify the error matches Zod validation
      const validation = resetPasswordSchema.safeParse(invalidData);
      expect(validation.success).toBe(false);
    });

    it('should reject password reset with invalid token', async () => {
      const response = await request(server)
        .post('/api/users/reset-password')
        .send({
          ...resetData,
          token: 'invalid-token'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/refresh-token', () => {
    it('should refresh token with valid refresh token', async () => {
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
    });

    it.each([
      ['missing refresh token', {}],
      ['invalid refresh token', { refreshToken: 'invalid-token' }],
      ['expired refresh token', { refreshToken: 'expired-token' }],
    ])('should reject token refresh with %s', async (description, invalidData) => {
      const response = await request(server)
        .post('/api/users/refresh-token')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/logout', () => {
    it('should logout successfully', async () => {
      const response = await request(server)
        .post('/api/users/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);

      // Verify token is invalidated
      await request(server)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);
    });
  });
});