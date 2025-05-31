import { Router } from 'express';
import { userController } from '../controllers/userController';
import { authenticate } from '../middleware/authMiddleware';
import { validate } from '../middleware/validationMiddleware';
import { asyncHandler } from '../middleware/errorHandler';
import {
  updateProfileSchema,
  changePasswordSchema
} from '../validators/userValidator';

const router = Router();

// All routes require authentication
router.use(asyncHandler(authenticate as any));

// Profile Management
router.get('/profile', userController.getProfile);
router.put('/profile', validate(updateProfileSchema), userController.updateProfile);
router.put('/change-password', validate(changePasswordSchema), userController.changePassword);

export default router;