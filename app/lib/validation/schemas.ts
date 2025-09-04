import { z } from 'zod';

// Authentication schemas
export const loginSchema = z.object({
  email: z.string().email('Invalid email format').min(1, 'Email is required'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

export const registerSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100, 'Name too long'),
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase, and number'),
});

// Poll schemas
export const pollQuestionSchema = z.string()
  .min(10, 'Question must be at least 10 characters')
  .max(500, 'Question too long')
  .regex(/^[a-zA-Z0-9\s\?\!\.\,\-\_\(\)\[\]]+$/, 'Question contains invalid characters');

export const pollOptionSchema = z.string()
  .min(1, 'Option cannot be empty')
  .max(200, 'Option too long')
  .regex(/^[a-zA-Z0-9\s\.\,\-\_\(\)\[\]]+$/, 'Option contains invalid characters');

export const createPollSchema = z.object({
  question: pollQuestionSchema,
  options: z.array(pollOptionSchema)
    .min(2, 'At least 2 options required')
    .max(10, 'Maximum 10 options allowed')
    .refine((options) => new Set(options).size === options.length, 'Options must be unique'),
});

export const updatePollSchema = createPollSchema;

export const voteSchema = z.object({
  pollId: z.string().uuid('Invalid poll ID'),
  optionIndex: z.number().int().min(0, 'Invalid option index'),
});

// Admin role check schema
export const adminRoleSchema = z.object({
  role: z.enum(['admin', 'super_admin']),
  permissions: z.array(z.string()).optional(),
});

// Rate limiting schemas
export const rateLimitSchema = z.object({
  identifier: z.string().min(1),
  action: z.enum(['vote', 'create_poll', 'delete_poll', 'login']),
  timestamp: z.number(),
});

export type LoginSchema = z.infer<typeof loginSchema>;
export type RegisterSchema = z.infer<typeof registerSchema>;
export type CreatePollSchema = z.infer<typeof createPollSchema>;
export type UpdatePollSchema = z.infer<typeof updatePollSchema>;
export type VoteSchema = z.infer<typeof voteSchema>;
