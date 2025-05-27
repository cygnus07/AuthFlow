import request from 'supertest';
import App from '../src/app';
import User from '../src/models/userModel';
import jwt from 'jsonwebtoken';
import { config } from '../src/config/environment';

describe('Auth Endpoints', () => {
  let app: App;
  let server: any;

  beforeAll(() => {
    app = new App();
    server = app.app;
  });

  describe('POST /api/users/register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
        username: 'johndoe'
      };

      const response = await request(server)
        .post('/api/users/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Registration successful');
      expect(response.body.data.user.email).toBe(userData.email);
      expect(response.body.data.user.password).toBeUndefined();

      // Verify user was created in database
      const user = await User.findOne({ email: userData.email });
      expect(user).toBeTruthy();
      expect(user?.emailVerified).toBe(false);
    });

    it('should reject duplicate email', async () => {
      const userData = {
        firstName: 'Jane',
        lastName: 'Doe',
        email: 'jane@example.com',
        password: 'password123'
      };

      // Create first user
      await request(server)
        .post('/api/users/register')
        .send(userData)
        .expect(201);

      // Try to create duplicate
      const response = await request(server)
        .post('/api/users/register')
        .send(userData)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('already');
    });

    it('should reject invalid email format', async () => {
      const userData = {
        firstName: 'Invalid',
        email: 'invalid-email',
        password: 'password123'
      };

      const response = await request(server)
        .post('/api/users/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('should reject weak password', async () => {
      const userData = {
        firstName: 'Test',
        email: 'test@example.com',
        password: '123' // Too short
      };

      const response = await request(server)
        .post('/api/users/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
    });
  });

  describe('POST /api/users/login', () => {
    let testUser: any;

    beforeEach(async () => {
      // Create a verified user for login tests
      const userData = {
        firstName: 'Login',
        lastName: 'Test',
        email: 'login@example.com',
        password: 'password123'
      };

      await request(server)
        .post('/api/users/register')
        .send(userData);

      // Manually verify the user for login tests
      testUser = await User.findOne({ email: userData.email });
      testUser.emailVerified = true;
      await testUser.save();
    });

    it('should login with valid credentials', async () => {
      const loginData = {
        email: 'login@example.com',
        password: 'password123'
      };

      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.user.email).toBe(loginData.email);
      expect(response.body.data.user.password).toBeUndefined();

      // Verify JWT token is valid
      const decoded = jwt.verify(response.body.data.accessToken, config.JWT_SECRET) as any;
      expect(decoded.userId).toBe(testUser._id.toString());
    });

    it('should reject invalid email', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123'
      };

      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');
    });

    it('should reject invalid password', async () => {
      const loginData = {
        email: 'login@example.com',
        password: 'wrongpassword'
      };

      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Invalid');
    });

    it('should reject unverified email', async () => {
      // Create unverified user
      const unverifiedData = {
        firstName: 'Unverified',
        email: 'unverified@example.com',
        password: 'password123'
      };

      await request(server)
        .post('/api/users/register')
        .send(unverifiedData);

      const loginData = {
        email: 'unverified@example.com',
        password: 'password123'
      };

      const response = await request(server)
        .post('/api/users/login')
        .send(loginData)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('verify');
    });
  });

  describe('Protected Routes', () => {
    let authToken: string;
    let testUser: any;

    beforeEach(async () => {
      // Create and verify user
      const userData = {
        firstName: 'Protected',
        lastName: 'Test',
        email: 'protected@example.com',
        password: 'password123'
      };

      await request(server)
        .post('/api/users/register')
        .send(userData);

      testUser = await User.findOne({ email: userData.email });
      testUser.emailVerified = true;
      await testUser.save();

      // Login to get token
      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      authToken = loginResponse.body.data.accessToken;
    });

    it('should access protected route with valid token', async () => {
      const response = await request(server)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.user.email).toBe('protected@example.com');
    });

    it('should reject request without token', async () => {
      const response = await request(server)
        .get('/api/users/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Authentication required');
    });

    it('should reject request with invalid token', async () => {
      const response = await request(server)
        .get('/api/users/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
    });

    it('should reject request with malformed authorization header', async () => {
      const response = await request(server)
        .get('/api/users/profile')
        .set('Authorization', 'InvalidFormat')
        .expect(401);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Logout', () => {
    let authToken: string;

    beforeEach(async () => {
      const userData = {
        firstName: 'Logout',
        email: 'logout@example.com',
        password: 'password123'
      };

      await request(server).post('/api/users/register').send(userData);
      
      const user = await User.findOne({ email: userData.email });
      if (!user) {
        throw new Error('User not found after registration');
        }
      user.emailVerified = true;
      await user.save();

      const loginResponse = await request(server)
        .post('/api/users/login')
        .send({ email: userData.email, password: userData.password });

      authToken = loginResponse.body.data.accessToken;
    });

    it('should logout successfully', async () => {
      const response = await request(server)
        .post('/api/users/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('Logout successful');

      // Token should be blacklisted - subsequent requests should fail
      await request(server)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);
    });
  });
});