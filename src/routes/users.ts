import { Router } from 'express';
import { userController } from '../controllers/userController.js';
import { authenticate, authorize, withAuth } from '../middleware/authMiddleware.js';
import { validate } from '../middleware/validationMiddleware.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  updateProfileSchema,
  changePasswordSchema,
  adminUpdateUserSchema,
  verifyEmailSchema,
  resendVerificationSchema,
  forgotPasswordSchema,
  resetPasswordSchema
} from '../validators/userValidator.js';

const router = Router();

// Public routes
router.post('/register', validate(registerSchema), userController.register);
router.post('/login', validate(loginSchema), userController.login);
router.post('/refresh-token', validate(refreshTokenSchema), userController.refreshToken);

// Password recovery routes
router.post('/forgot-password', validate(forgotPasswordSchema), userController.forgotPassword);
router.post('/reset-password', validate(resetPasswordSchema), userController.resetPassword);

// Email verification routes
router.post('/verify-email', validate(verifyEmailSchema), userController.verifyEmail);
router.post('/resend-verification', validate(resendVerificationSchema), userController.resendVerificationEmail);

// Google OAuth routes
router.get('/auth/google', userController.googleAuth);
router.get('/auth/google/callback', userController.googleCallback);

// Authenticated user routes
router.use(asyncHandler(authenticate as any));
router.get('/profile', userController.getProfile);
router.put('/profile', validate(updateProfileSchema), userController.updateProfile);
router.put('/change-password', validate(changePasswordSchema), userController.changePassword);
router.post('/logout', userController.logout);

// Admin-only routes
router.use(authorize('admin'));
router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUserById);
router.put('/:id', validate(adminUpdateUserSchema), userController.updateUser);
router.delete('/:id', userController.deleteUser);

export default router;
