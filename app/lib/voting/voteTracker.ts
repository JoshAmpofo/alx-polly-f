import { createClient } from '@/lib/supabase/server';

export interface VoteRecord {
  id: string;
  poll_id: string;
  user_id: string | null;
  option_index: number;
  ip_address?: string;
  created_at: string;
}

/**
 * Check if user has already voted on a poll
 */
export async function hasUserVoted(pollId: string, userId?: string, ipAddress?: string): Promise<boolean> {
  const supabase = await createClient();
  
  let query = supabase
    .from('votes')
    .select('id')
    .eq('poll_id', pollId);
  
  if (userId) {
    // Check for authenticated user vote
    query = query.eq('user_id', userId);
  } else if (ipAddress) {
    // Check for anonymous vote by IP
    query = query.eq('ip_address', ipAddress).is('user_id', null);
  } else {
    return false; // No identifier to check
  }
  
  const { data, error } = await query.limit(1);
  
  if (error) {
    console.error('Error checking vote status:', error);
    return false;
  }
  
  return data && data.length > 0;
}

/**
 * Record a vote with duplicate prevention
 */
export async function recordVote(
  pollId: string, 
  optionIndex: number, 
  userId?: string, 
  ipAddress?: string
): Promise<{ success: boolean; error?: string }> {
  const supabase = await createClient();
  
  // Check if user has already voted
  const alreadyVoted = await hasUserVoted(pollId, userId, ipAddress);
  if (alreadyVoted) {
    return { success: false, error: 'You have already voted on this poll' };
  }
  
  // Verify the poll exists and option index is valid
  const { data: poll, error: pollError } = await supabase
    .from('polls')
    .select('options')
    .eq('id', pollId)
    .single();
    
  if (pollError || !poll) {
    return { success: false, error: 'Poll not found' };
  }
  
  if (optionIndex < 0 || optionIndex >= poll.options.length) {
    return { success: false, error: 'Invalid option selected' };
  }
  
  // Record the vote
  const { error: insertError } = await supabase
    .from('votes')
    .insert([{
      poll_id: pollId,
      user_id: userId || null,
      option_index: optionIndex,
      ip_address: userId ? null : ipAddress, // Only store IP for anonymous votes
    }]);
    
  if (insertError) {
    console.error('Error recording vote:', insertError);
    return { success: false, error: 'Failed to record vote' };
  }
  
  return { success: true };
}

/**
 * Get vote statistics for a poll
 */
export async function getPollVoteStats(pollId: string): Promise<{
  totalVotes: number;
  optionCounts: number[];
  error?: string;
}> {
  const supabase = await createClient();
  
  // Get poll options
  const { data: poll, error: pollError } = await supabase
    .from('polls')
    .select('options')
    .eq('id', pollId)
    .single();
    
  if (pollError || !poll) {
    return { totalVotes: 0, optionCounts: [], error: 'Poll not found' };
  }
  
  // Get all votes for this poll
  const { data: votes, error: votesError } = await supabase
    .from('votes')
    .select('option_index')
    .eq('poll_id', pollId);
    
  if (votesError) {
    console.error('Error fetching votes:', votesError);
    return { totalVotes: 0, optionCounts: [], error: 'Failed to fetch votes' };
  }
  
  // Count votes for each option
  const optionCounts = new Array(poll.options.length).fill(0);
  
  if (votes) {
    votes.forEach(vote => {
      if (vote.option_index >= 0 && vote.option_index < optionCounts.length) {
        optionCounts[vote.option_index]++;
      }
    });
  }
  
  return {
    totalVotes: votes?.length || 0,
    optionCounts,
  };
}

/**
 * Clean up old anonymous votes (for privacy and storage management)
 */
export async function cleanupOldAnonymousVotes(daysOld: number = 90): Promise<void> {
  const supabase = await createClient();
  const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);
  
  const { error } = await supabase
    .from('votes')
    .delete()
    .is('user_id', null)
    .lt('created_at', cutoffDate.toISOString());
    
  if (error) {
    console.error('Error cleaning up old votes:', error);
  }
}
