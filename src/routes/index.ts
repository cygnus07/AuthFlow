import { Router } from 'express';
import healthRoutes from './health';
import authRoutes from './authRoutes';
import userRoutes from './userRoutes';
import adminRoutes from './adminRoutes';

const router = Router();

// System routes
router.use('/health', healthRoutes);

// Authentication routes (public)
router.use('/auth', authRoutes);

// Authenticated user routes (requires login)
router.use('/users', userRoutes);

// Admin routes (requires admin role)
router.use('/admin', adminRoutes);

export default router;