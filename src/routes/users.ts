import { Router, Request, Response } from 'express';
import { asyncHandler, AppError } from '@/middleware/errorHandler';

const router = Router();

// Example user interface
interface User {
  id: string;
  name: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;
}

// Mock data for demonstration
const mockUsers: User[] = [
  {
    id: '1',
    name: 'John Doe',
    email: 'john@example.com',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  },
  {
    id: '2',
    name: 'Jane Smith',
    email: 'jane@example.com',
    createdAt: new Date('2024-01-02'),
    updatedAt: new Date('2024-01-02'),
  },
];

// GET /api/users - Get all users
router.get('/', asyncHandler(async (req: Request, res: Response) => {
  // Parse query parameters
 // Parse query parameters
const page = parseInt((req.query['page'] as string) ?? '1', 10);
const limit = parseInt((req.query['limit'] as string) ?? '10', 10);
const search = req.query['search'] as string | undefined;

  let filteredUsers = mockUsers;

  // Apply search filter
  if (search) {
    filteredUsers = mockUsers.filter(user => 
      user.name.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
    );
  }

  // Apply pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

  res.json({
    success: true,
    data: {
      users: paginatedUsers,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(filteredUsers.length / limit),
        totalUsers: filteredUsers.length,
        hasNextPage: endIndex < filteredUsers.length,
        hasPrevPage: page > 1,
      },
    },
  });
}));

// GET /api/users/:id - Get user by ID
router.get('/:id', asyncHandler(async (req: Request, res: Response) => {
  const { id } = req.params;
  
  const user = mockUsers.find(u => u.id === id);
  
  if (!user) {
    throw new AppError('User not found', 404);
  }

  res.json({
    success: true,
    data: { user },
  });
}));

// POST /api/users - Create new user
router.post('/', asyncHandler(async (req: Request, res: Response) => {
  const { name, email } = req.body;

  // Basic validation
  if (!name || !email) {
    throw new AppError('Name and email are required', 400);
  }

  // Check if email already exists
  const existingUser = mockUsers.find(u => u.email === email);
  if (existingUser) {
    throw new AppError('Email already exists', 409);
  }

  // Create new user
  const newUser: User = {
    id: (mockUsers.length + 1).toString(),
    name,
    email,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  mockUsers.push(newUser);

  res.status(201).json({
    success: true,
    message: 'User created successfully',
    data: { user: newUser },
  });
}));

// PUT /api/users/:id - Update user
router.put('/:id', asyncHandler(async (req: Request, res: Response) => {
  const { id } = req.params;
  const { name, email } = req.body;

  const userIndex = mockUsers.findIndex(u => u.id === id);
  
  if (userIndex === -1) {
    throw new AppError('User not found', 404);
  }

  // Check if email already exists (excluding current user)
  if (email) {
    const existingUser = mockUsers.find(u => u.email === email && u.id !== id);
    if (existingUser) {
      throw new AppError('Email already exists', 409);
    }
  }

  // Update user
  const updatedUser = {
    ...mockUsers[userIndex],
    ...(name && { name }),
    ...(email && { email }),
    updatedAt: new Date(),
  };

  mockUsers[userIndex] = updatedUser;

  res.json({
    success: true,
    message: 'User updated successfully',
    data: { user: updatedUser },
  });
}));

// DELETE /api/users/:id - Delete user
router.delete('/:id', asyncHandler(async (req: Request, res: Response) => {
  const { id } = req.params;

  const userIndex = mockUsers.findIndex(u => u.id === id);
  
  if (userIndex === -1) {
    throw new AppError('User not found', 404);
  }

  mockUsers.splice(userIndex, 1);

  res.json({
    success: true,
    message: 'User deleted successfully',
  });
}));

export default router;