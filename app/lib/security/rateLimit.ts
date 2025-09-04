interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  identifier: string;
}

interface RateLimitData {
  count: number;
  resetTime: number;
}

// In-memory storage for rate limiting (in production, use Redis)
const rateLimitStore = new Map<string, RateLimitData>();

/**
 * Clean up expired rate limit entries
 */
function cleanupExpiredEntries(): void {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now > data.resetTime) {
      rateLimitStore.delete(key);
    }
  }
}

/**
 * Check and update rate limit for a given identifier
 */
export function checkRateLimit(config: RateLimitConfig): {
  allowed: boolean;
  remaining: number;
  resetTime: number;
} {
  cleanupExpiredEntries();
  
  const now = Date.now();
  const key = `${config.identifier}`;
  const existing = rateLimitStore.get(key);
  
  if (!existing || now > existing.resetTime) {
    // First request or window expired, create new entry
    const resetTime = now + config.windowMs;
    rateLimitStore.set(key, { count: 1, resetTime });
    
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetTime
    };
  }
  
  // Window is still active
  if (existing.count >= config.maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetTime: existing.resetTime
    };
  }
  
  // Increment counter
  existing.count++;
  rateLimitStore.set(key, existing);
  
  return {
    allowed: true,
    remaining: config.maxRequests - existing.count,
    resetTime: existing.resetTime
  };
}

/**
 * Rate limit configurations for different actions
 */
export const RATE_LIMITS = {
  login: {
    maxRequests: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
  },
  vote: {
    maxRequests: 10,
    windowMs: 60 * 1000, // 1 minute
  },
  createPoll: {
    maxRequests: 5,
    windowMs: 60 * 60 * 1000, // 1 hour
  },
  deletePoll: {
    maxRequests: 10,
    windowMs: 60 * 60 * 1000, // 1 hour
  },
  adminActions: {
    maxRequests: 20,
    windowMs: 60 * 60 * 1000, // 1 hour
  }
} as const;

/**
 * Get client identifier for rate limiting
 */
export function getClientIdentifier(request: Request, userId?: string): string {
  // Use user ID if available, otherwise fall back to IP
  if (userId) {
    return `user:${userId}`;
  }
  
  // Get IP from various headers
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const cfIp = request.headers.get('cf-connecting-ip');
  
  const ip = forwarded?.split(',')[0] || realIp || cfIp || 'unknown';
  
  return `ip:${ip}`;
}

/**
 * Validate rate limit and throw error if exceeded
 */
export function enforceRateLimit(config: RateLimitConfig): void {
  const result = checkRateLimit(config);
  
  if (!result.allowed) {
    const resetTimeSeconds = Math.ceil((result.resetTime - Date.now()) / 1000);
    throw new Error(`Rate limit exceeded. Try again in ${resetTimeSeconds} seconds.`);
  }
}
