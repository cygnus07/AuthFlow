import { Router } from 'express';
import { adminController } from '../controllers/adminController';
import { authenticate,authorize } from '../middleware/authMiddleware';
import { validate } from '../middleware/validationMiddleware';
import { asyncHandler } from '../middleware/errorHandler';
import { adminUpdateUserSchema } from '../validators/userValidator';

const router = Router();

// Require admin privileges
router.use(asyncHandler(authenticate));
router.use(asyncHandler(authorize('admin') as any));

// User Management
router.get('/', adminController.getAllUsers);
router.get('/:id', adminController.getUserById);
router.put('/:id', validate(adminUpdateUserSchema), adminController.updateUser);
router.delete('/:id', adminController.deleteUser);

export default router;