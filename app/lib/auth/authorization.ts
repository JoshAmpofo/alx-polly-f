import { createClient } from '@/lib/supabase/server';

export interface UserRole {
  id: string;
  user_id: string;
  role: 'user' | 'admin' | 'super_admin';
  created_at: string;
}

export interface AuthorizedUser {
  id: string;
  email: string;
  role: string;
}

/**
 * Get current user with role information
 */
export async function getCurrentUserWithRole(): Promise<AuthorizedUser | null> {
  const supabase = await createClient();
  
  const { data: { user }, error: userError } = await supabase.auth.getUser();
  if (userError || !user) return null;

  // Get user role from user_roles table
  const { data: roleData, error: roleError } = await supabase
    .from('user_roles')
    .select('role')
    .eq('user_id', user.id)
    .single();

  if (roleError || !roleData) {
    // Default role is 'user'
    return {
      id: user.id,
      email: user.email!,
      role: 'user'
    };
  }

  return {
    id: user.id,
    email: user.email!,
    role: roleData.role
  };
}

/**
 * Check if user has admin privileges
 */
export async function isAdmin(userId?: string): Promise<boolean> {
  const supabase = await createClient();
  
  let targetUserId = userId;
  if (!targetUserId) {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;
    targetUserId = user.id;
  }

  const { data, error } = await supabase
    .from('user_roles')
    .select('role')
    .eq('user_id', targetUserId)
    .single();

  if (error || !data) return false;
  
  return data.role === 'admin' || data.role === 'super_admin';
}

/**
 * Verify poll ownership
 */
export async function verifyPollOwnership(pollId: string, userId?: string): Promise<boolean> {
  const supabase = await createClient();
  
  let targetUserId = userId;
  if (!targetUserId) {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;
    targetUserId = user.id;
  }

  const { data, error } = await supabase
    .from('polls')
    .select('user_id')
    .eq('id', pollId)
    .single();

  if (error || !data) return false;
  
  return data.user_id === targetUserId;
}

/**
 * Check if user can perform admin actions
 */
export async function requireAdmin(): Promise<AuthorizedUser> {
  const user = await getCurrentUserWithRole();
  
  if (!user) {
    throw new Error('Authentication required');
  }
  
  if (user.role !== 'admin' && user.role !== 'super_admin') {
    throw new Error('Admin privileges required');
  }
  
  return user;
}

/**
 * Check if user can modify poll (owner or admin)
 */
export async function canModifyPoll(pollId: string): Promise<{ canModify: boolean; user: AuthorizedUser }> {
  const user = await getCurrentUserWithRole();
  
  if (!user) {
    throw new Error('Authentication required');
  }

  // Admins can modify any poll
  if (user.role === 'admin' || user.role === 'super_admin') {
    return { canModify: true, user };
  }

  // Check ownership for regular users
  const isOwner = await verifyPollOwnership(pollId, user.id);
  
  return { canModify: isOwner, user };
}
