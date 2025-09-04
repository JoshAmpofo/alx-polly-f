import DOMPurify from 'isomorphic-dompurify';

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param input - Raw HTML string to sanitize
 * @returns Sanitized HTML string
 */
export function sanitizeHtml(input: string): string {
  if (!input) return '';
  
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
  });
}

/**
 * Sanitizes text input for safe display
 * @param input - Raw text input
 * @returns Sanitized text
 */
export function sanitizeText(input: string): string {
  if (!input) return '';
  
  // Remove HTML tags and decode entities
  return input
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .trim();
}

/**
 * Escape special characters for safe URL usage
 * @param input - String to escape
 * @returns URL-safe string
 */
export function escapeForUrl(input: string): string {
  if (!input) return '';
  
  return encodeURIComponent(sanitizeText(input));
}

/**
 * Sanitizes form data object
 * @param data - Form data object
 * @returns Sanitized form data
 */
export function sanitizeFormData(data: Record<string, any>): Record<string, any> {
  const sanitized: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeText(value);
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map(item => 
        typeof item === 'string' ? sanitizeText(item) : item
      );
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Validates and sanitizes poll question
 * @param question - Raw poll question
 * @returns Sanitized question
 */
export function sanitizePollQuestion(question: string): string {
  const sanitized = sanitizeText(question);
  
  // Additional validation for poll questions
  if (sanitized.length < 10) {
    throw new Error('Poll question must be at least 10 characters');
  }
  
  if (sanitized.length > 500) {
    throw new Error('Poll question too long');
  }
  
  return sanitized;
}

/**
 * Validates and sanitizes poll options
 * @param options - Array of raw poll options
 * @returns Array of sanitized options
 */
export function sanitizePollOptions(options: string[]): string[] {
  const sanitized = options
    .map(option => sanitizeText(option))
    .filter(option => option.length > 0);
  
  if (sanitized.length < 2) {
    throw new Error('At least 2 options are required');
  }
  
  if (sanitized.length > 10) {
    throw new Error('Maximum 10 options allowed');
  }
  
  // Check for duplicate options
  const uniqueOptions = new Set(sanitized.map(opt => opt.toLowerCase()));
  if (uniqueOptions.size !== sanitized.length) {
    throw new Error('Poll options must be unique');
  }
  
  return sanitized;
}
