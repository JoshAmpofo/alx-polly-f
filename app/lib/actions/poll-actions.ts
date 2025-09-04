"use server";

import { createClient } from "@/lib/supabase/server";
import { revalidatePath } from "next/cache";
import { createPollSchema, updatePollSchema, voteSchema } from "../validation/schemas";
import { sanitizePollQuestion, sanitizePollOptions } from "../utils/sanitizer";
import { validateCSRFToken } from "../security/csrf";
import { enforceRateLimit, getClientIdentifier, RATE_LIMITS } from "../security/rateLimit";
import { requireAdmin, canModifyPoll, getCurrentUserWithRole } from "../auth/authorization";
import { recordVote, getPollVoteStats, hasUserVoted } from "../voting/voteTracker";
import { headers } from "next/headers";

// CREATE POLL
export async function createPoll(formData: FormData) {
  try {
    const headersList = await headers();
    
    // CSRF Protection
    await validateCSRFToken(formData);
    
    const supabase = await createClient();
    
    // Authentication check
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      return { error: "You must be logged in to create a poll." };
    }
    
    // Rate limiting
    enforceRateLimit({
      ...RATE_LIMITS.createPoll,
      identifier: `user:${user.id}`,
    });
    
    // Extract and validate form data
    const question = formData.get("question") as string;
    const options = formData.getAll("options").filter(Boolean) as string[];
    
    // Sanitize inputs
    const sanitizedQuestion = sanitizePollQuestion(question);
    const sanitizedOptions = sanitizePollOptions(options);
    
    // Validate with schema
    const validatedData = createPollSchema.parse({
      question: sanitizedQuestion,
      options: sanitizedOptions,
    });

    const { error } = await supabase.from("polls").insert([
      {
        user_id: user.id,
        question: validatedData.question,
        options: validatedData.options,
      },
    ]);

    if (error) {
      console.error('Poll creation error:', error);
      return { error: "Failed to create poll. Please try again." };
    }

    revalidatePath("/polls");
    return { error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: "Failed to create poll" };
  }
}

// GET USER POLLS
export async function getUserPolls() {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    
    if (!user) return { polls: [], error: "Not authenticated" };

    const { data, error } = await supabase
      .from("polls")
      .select("id, question, options, created_at, user_id")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error('Error fetching user polls:', error);
      return { polls: [], error: "Failed to fetch polls" };
    }
    
    return { polls: data ?? [], error: null };
  } catch (error) {
    return { polls: [], error: "Failed to fetch polls" };
  }
}

// GET POLL BY ID with vote statistics
export async function getPollById(id: string) {
  try {
    // Validate poll ID format
    if (!id || typeof id !== 'string' || id.length < 10) {
      return { poll: null, error: "Invalid poll ID" };
    }
    
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("polls")
      .select("id, question, options, created_at, user_id")
      .eq("id", id)
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return { poll: null, error: "Poll not found" };
      }
      return { poll: null, error: "Failed to fetch poll" };
    }
    
    // Get vote statistics
    const voteStats = await getPollVoteStats(id);
    
    return { 
      poll: {
        ...data,
        voteStats: voteStats
      }, 
      error: null 
    };
  } catch (error) {
    return { poll: null, error: "Failed to fetch poll" };
  }
}

// SUBMIT VOTE with duplicate prevention and rate limiting
export async function submitVote(pollId: string, optionIndex: number, formData?: FormData, request?: Request) {
  try {
    // CSRF Protection if form data provided
    if (formData) {
      await validateCSRFToken(formData);
    }
    
    // Input validation
    const validatedData = voteSchema.parse({ pollId, optionIndex });
    
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    
    // Get client identifier for rate limiting
    let clientId: string;
    let ipAddress: string | undefined;
    
    if (request) {
      clientId = getClientIdentifier(request, user?.id);
      
      // Extract IP for anonymous vote tracking
      if (!user) {
        const forwarded = request.headers.get('x-forwarded-for');
        const realIp = request.headers.get('x-real-ip');
        ipAddress = forwarded?.split(',')[0] || realIp || undefined;
      }
    } else {
      clientId = user?.id || 'anonymous';
    }
    
    // Rate limiting
    enforceRateLimit({
      ...RATE_LIMITS.vote,
      identifier: clientId,
    });
    
    // Record vote with duplicate prevention
    const voteResult = await recordVote(
      validatedData.pollId,
      validatedData.optionIndex,
      user?.id,
      ipAddress
    );
    
    if (!voteResult.success) {
      return { error: voteResult.error };
    }
    
    revalidatePath(`/polls/${pollId}`);
    return { error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: "Failed to submit vote" };
  }
}

// DELETE POLL with proper authorization
export async function deletePoll(id: string, formData?: FormData) {
  try {
    // CSRF Protection if form data provided
    if (formData) {
      await validateCSRFToken(formData);
    }
    
    // Validate poll ID
    if (!id || typeof id !== 'string') {
      return { error: "Invalid poll ID" };
    }
    
    const supabase = await createClient();
    
    // Check authorization (owner or admin)
    const { canModify, user } = await canModifyPoll(id);
    if (!canModify) {
      return { error: "Not authorized to delete this poll" };
    }
    
    // Rate limiting
    enforceRateLimit({
      ...RATE_LIMITS.deletePoll,
      identifier: `user:${user.id}`,
    });
    
    // Delete associated votes first (cascade delete)
    await supabase.from("votes").delete().eq("poll_id", id);
    
    // Delete the poll
    const { error } = await supabase.from("polls").delete().eq("id", id);
    
    if (error) {
      console.error('Poll deletion error:', error);
      return { error: "Failed to delete poll" };
    }
    
    revalidatePath("/polls");
    return { error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: "Failed to delete poll" };
  }
}

// UPDATE POLL with proper authorization and validation
export async function updatePoll(pollId: string, formData: FormData) {
  try {
    // CSRF Protection
    await validateCSRFToken(formData);
    
    // Check authorization
    const { canModify, user } = await canModifyPoll(pollId);
    if (!canModify) {
      return { error: "Not authorized to update this poll" };
    }
    
    // Extract and validate form data
    const question = formData.get("question") as string;
    const options = formData.getAll("options").filter(Boolean) as string[];
    
    // Sanitize inputs
    const sanitizedQuestion = sanitizePollQuestion(question);
    const sanitizedOptions = sanitizePollOptions(options);
    
    // Validate with schema
    const validatedData = updatePollSchema.parse({
      question: sanitizedQuestion,
      options: sanitizedOptions,
    });

    const supabase = await createClient();
    
    // Update poll with ownership verification
    const { error } = await supabase
      .from("polls")
      .update({ 
        question: validatedData.question, 
        options: validatedData.options,
        updated_at: new Date().toISOString()
      })
      .eq("id", pollId)
      .eq("user_id", user.id); // Double-check ownership

    if (error) {
      console.error('Poll update error:', error);
      return { error: "Failed to update poll" };
    }

    revalidatePath(`/polls/${pollId}`);
    return { error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }
    return { error: "Failed to update poll" };
  }
}

// ADMIN: Get all polls with proper authorization
export async function getAllPolls() {
  try {
    // Require admin privileges
    const admin = await requireAdmin();
    
    // Rate limiting for admin actions
    enforceRateLimit({
      ...RATE_LIMITS.adminActions,
      identifier: `admin:${admin.id}`,
    });
    
    const supabase = await createClient();
    const { data, error } = await supabase
      .from("polls")
      .select("id, question, options, created_at, user_id")
      .order("created_at", { ascending: false })
      .limit(100); // Limit results to prevent excessive data exposure

    if (error) {
      console.error('Error fetching all polls:', error);
      return { polls: [], error: "Failed to fetch polls" };
    }
    
    return { polls: data ?? [], error: null };
    
  } catch (error) {
    if (error instanceof Error) {
      return { polls: [], error: error.message };
    }
    return { polls: [], error: "Access denied" };
  }
}

// Check if user has already voted on a poll
export async function checkVoteStatus(pollId: string, request?: Request) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    
    let ipAddress: string | undefined;
    if (request && !user) {
      const forwarded = request.headers.get('x-forwarded-for');
      const realIp = request.headers.get('x-real-ip');
      ipAddress = forwarded?.split(',')[0] || realIp || undefined;
    }
    
    const hasVoted = await hasUserVoted(pollId, user?.id, ipAddress);
    return { hasVoted, error: null };
    
  } catch (error) {
    return { hasVoted: false, error: "Failed to check vote status" };
  }
}
