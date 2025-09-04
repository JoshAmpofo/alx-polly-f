'use server';

import { createClient } from '@/lib/supabase/server';
import { LoginFormData, RegisterFormData } from '../types';
import { loginSchema, registerSchema } from '../validation/schemas';
import { sanitizeFormData } from '../utils/sanitizer';
import { validateCSRFToken } from '../security/csrf';
import { enforceRateLimit, getClientIdentifier, RATE_LIMITS } from '../security/rateLimit';
import { redirect } from 'next/navigation';

export async function login(data: LoginFormData, formData: FormData, request?: Request) {
  try {
    // CSRF Protection
    await validateCSRFToken(formData);
    
    // Rate Limiting
    if (request) {
      const identifier = getClientIdentifier(request);
      enforceRateLimit({
        ...RATE_LIMITS.login,
        identifier,
      });
    }
    
    // Input Validation and Sanitization
    const sanitizedData = sanitizeFormData(data);
    const validatedData = loginSchema.parse(sanitizedData);
    
    const supabase = await createClient();
    
    const { error } = await supabase.auth.signInWithPassword({
      email: validatedData.email,
      password: validatedData.password,
    });

    if (error) {
      return { error: 'Invalid email or password' }; // Generic error message
    }

    // Success: redirect server-side
    redirect('/polls');
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: 'Authentication failed' };
  }
}

export async function register(data: RegisterFormData, formData: FormData, request?: Request) {
  try {
    // CSRF Protection
    await validateCSRFToken(formData);
    
    // Rate Limiting
    if (request) {
      const identifier = getClientIdentifier(request);
      enforceRateLimit({
        maxRequests: 3,
        windowMs: 60 * 60 * 1000, // 1 hour
        identifier,
      });
    }
    
    // Input Validation and Sanitization
    const sanitizedData = sanitizeFormData(data);
    const validatedData = registerSchema.parse(sanitizedData);
    
    const supabase = await createClient();

    const { error } = await supabase.auth.signUp({
      email: validatedData.email,
      password: validatedData.password,
      options: {
        data: {
          name: validatedData.name,
        },
      },
    });

    if (error) {
      if (error.message.includes('already registered')) {
        return { error: 'An account with this email already exists' };
      }
      return { error: 'Registration failed' };
    }

    return { error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: 'Registration failed' };
  }
}

export async function logout() {
  try {
    const supabase = await createClient();
    const { error } = await supabase.auth.signOut();
    if (error) {
      return { error: 'Logout failed' };
    }
    
    // Server-side redirect after logout
    redirect('/login');
    
  } catch (error) {
    return { error: 'Logout failed' };
  }
}

export async function getCurrentUser() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getUser();
  return data.user;
}

export async function getSession() {
  const supabase = await createClient();
  const { data } = await supabase.auth.getSession();
  return data.session;
}
