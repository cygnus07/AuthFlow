import { Router } from 'express';
import healthRoutes from './health';
import userRoutes from './users';
// Import other route modules here

const router = Router();

// API Routes
router.use('/health', healthRoutes);
router.use('/users', userRoutes);
// Add other routes here
// router.use('/auth', authRoutes);
// router.use('/posts', postRoutes);

export default router;