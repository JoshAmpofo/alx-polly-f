import { cookies } from 'next/headers';
import crypto from 'crypto';

const CSRF_TOKEN_NAME = 'csrf-token';
const CSRF_TOKEN_LENGTH = 32;

/**
 * Generate a cryptographically secure CSRF token
 */
export function generateCSRFToken(): string {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
}

/**
 * Set CSRF token in cookies
 */
export async function setCSRFToken(): Promise<string> {
  const token = generateCSRFToken();
  const cookieStore = await cookies();
  
  cookieStore.set(CSRF_TOKEN_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24, // 24 hours
    path: '/',
  });
  
  return token;
}

/**
 * Get CSRF token from cookies
 */
export async function getCSRFToken(): Promise<string | null> {
  const cookieStore = await cookies();
  const token = cookieStore.get(CSRF_TOKEN_NAME);
  return token?.value || null;
}

/**
 * Verify CSRF token
 */
export async function verifyCSRFToken(submittedToken: string): Promise<boolean> {
  if (!submittedToken) {
    return false;
  }
  
  const storedToken = await getCSRFToken();
  if (!storedToken) {
    return false;
  }
  
  // Use constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(submittedToken, 'hex'),
    Buffer.from(storedToken, 'hex')
  );
}

/**
 * Middleware function to validate CSRF token for form submissions
 */
export async function validateCSRFToken(formData: FormData): Promise<void> {
  const token = formData.get('csrf-token') as string;
  
  if (!token) {
    throw new Error('CSRF token is required');
  }
  
  const isValid = await verifyCSRFToken(token);
  if (!isValid) {
    throw new Error('Invalid CSRF token');
  }
}

/**
 * Get CSRF token for client-side usage (non-HttpOnly version)
 */
export async function getClientCSRFToken(): Promise<string> {
  const cookieStore = await cookies();
  const token = cookieStore.get('csrf-token-client');
  
  if (token) {
    return token.value;
  }
  
  // Generate new token if not exists
  const newToken = generateCSRFToken();
  cookieStore.set('csrf-token-client', newToken, {
    httpOnly: false, // Accessible to client-side JavaScript
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24, // 24 hours
    path: '/',
  });
  
  return newToken;
}
