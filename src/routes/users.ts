import { Router } from 'express';
import { userController } from '../controllers/userController.js';
import { authenticate, authorize } from '../middlewares/auth.middleware.js';
import { validate } from '../middlewares/validation.middleware.js';
import { withAuth } from '../middlewares/auth.middleware.js';
import { 
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  updateProfileSchema,
  changePasswordSchema,
  adminUpdateUserSchema,
  verifyEmailSchema,
  resendVerificationSchema,
  ForgotPasswordInput,
  ResetPasswordInput
} from '../validators/userValidator.js';

const router = Router();

// Public routes
router.post('/register', validate(registerSchema), userController.register);
router.post('/login', validate(loginSchema), userController.login);
router.post('/refresh-token', validate(refreshTokenSchema), userController.refreshToken);

// Password recovery routes
router.post('/forgot-password', validate(ForgotPasswordInput), userController.forgotPassword);
router.post('/reset-password', validate(ResetPasswordInput), userController.resetPassword);

// Email verification and password reset routes
router.post('/verify-email', validate(verifyEmailSchema), userController.verifyEmail);
router.post('/resend-verification', validate(resendVerificationSchema), userController.resendVerificationEmail);

// Google OAuth routes
router.get('/auth/google', userController.googleAuth);
router.get('/auth/google/callback', userController.googleCallback);

// Facebook OAuth routes
// router.get('/auth/facebook', userController.facebookAuth);
// router.get('/auth/facebook/callback', userController.facebookCallback);


// Authenticated routes
router.use(authenticate);
router.get('/profile', userController.getProfile);
router.put('/profile', validate(updateProfileSchema), withAuth(userController.updateProfile));
router.put('/change-password', validate(changePasswordSchema), withAuth(userController.changePassword));
router.post('/logout', userController.logout);

// Admin routes
router.use(authorize('admin'));
router.get('/', userController.getAllUsers);
router.get('/:id', userController.getUserById);
router.put('/:id', validate(adminUpdateUserSchema), userController.updateUser);
router.delete('/:id', userController.deleteUser);
export default router;