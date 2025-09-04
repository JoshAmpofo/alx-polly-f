"use client";

import { useState, useEffect } from "react";
import { createPoll } from "@/app/lib/actions/poll-actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { sanitizeText } from "@/app/lib/utils/sanitizer";

export default function PollCreateForm() {
  const [options, setOptions] = useState(["", ""]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [csrfToken, setCsrfToken] = useState('');
  const [loading, setLoading] = useState(false);

  // Get CSRF token on component mount
  useEffect(() => {
    const fetchCSRFToken = async () => {
      try {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        setCsrfToken(data.token);
      } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
      }
    };

    fetchCSRFToken();
  }, []);

  const handleOptionChange = (idx: number, value: string) => {
    // Sanitize input as user types
    const sanitizedValue = sanitizeText(value);
    setOptions((opts) => opts.map((opt, i) => (i === idx ? sanitizedValue : opt)));
  };

  const addOption = () => {
    if (options.length < 10) {
      setOptions((opts) => [...opts, ""]);
    }
  };
  
  const removeOption = (idx: number) => {
    if (options.length > 2) {
      setOptions((opts) => opts.filter((_, i) => i !== idx));
    }
  };

  const validateForm = (question: string, options: string[]): string | null => {
    if (!question.trim()) return "Poll question is required";
    if (question.length < 10) return "Poll question must be at least 10 characters";
    if (question.length > 500) return "Poll question is too long";
    
    const validOptions = options.filter(opt => opt.trim().length > 0);
    if (validOptions.length < 2) return "At least 2 options are required";
    if (validOptions.length > 10) return "Maximum 10 options allowed";
    
    // Check for duplicate options
    const uniqueOptions = new Set(validOptions.map(opt => opt.toLowerCase().trim()));
    if (uniqueOptions.size !== validOptions.length) {
      return "Options must be unique";
    }
    
    return null;
  };

  return (
    <form
      action={async (formData) => {
        setError(null);
        setSuccess(false);
        setLoading(true);
        
        try {
          const question = formData.get("question") as string;
          
          // Client-side validation
          const validationError = validateForm(question, options);
          if (validationError) {
            setError(validationError);
            setLoading(false);
            return;
          }
          
          // Add CSRF token
          formData.append('csrf-token', csrfToken);
          
          const res = await createPoll(formData);
          
          if (res?.error) {
            setError(res.error);
          } else {
            setSuccess(true);
            setTimeout(() => {
              window.location.href = "/polls";
            }, 1200);
          }
        } catch (error) {
          setError("Failed to create poll. Please try again.");
        } finally {
          setLoading(false);
        }
      }}
      className="space-y-6 max-w-md mx-auto"
    >
      <input type="hidden" name="csrf-token" value={csrfToken} />
      
      <div>
        <Label htmlFor="question">Poll Question</Label>
        <Input 
          name="question" 
          id="question" 
          required 
          maxLength={500}
          placeholder="Enter your poll question (10-500 characters)"
          disabled={loading}
        />
      </div>
      
      <div>
        <Label>Options ({options.filter(opt => opt.trim()).length}/10)</Label>
        {options.map((opt, idx) => (
          <div key={idx} className="flex items-center gap-2 mb-2">
            <Input
              name="options"
              value={opt}
              onChange={(e) => handleOptionChange(idx, e.target.value)}
              required
              maxLength={200}
              placeholder={`Option ${idx + 1}`}
              disabled={loading}
            />
            {options.length > 2 && (
              <Button 
                type="button" 
                variant="destructive" 
                onClick={() => removeOption(idx)}
                disabled={loading}
              >
                Remove
              </Button>
            )}
          </div>
        ))}
        
        <div className="flex gap-2 mt-2">
          <Button 
            type="button" 
            onClick={addOption} 
            variant="secondary"
            disabled={options.length >= 10 || loading}
          >
            Add Option ({options.length}/10)
          </Button>
        </div>
      </div>
      
      {error && (
        <div className="text-red-500 p-3 bg-red-50 rounded border border-red-200">
          {error}
        </div>
      )}
      
      {success && (
        <div className="text-green-600 p-3 bg-green-50 rounded border border-green-200">
          Poll created successfully! Redirecting...
        </div>
      )}
      
      <Button 
        type="submit" 
        disabled={loading || !csrfToken || options.filter(opt => opt.trim()).length < 2}
        className="w-full"
      >
        {loading ? "Creating Poll..." : "Create Poll"}
      </Button>
      
      <div className="text-xs text-gray-500 mt-4 p-3 bg-gray-50 rounded">
        <strong>Guidelines:</strong> Keep your poll question clear and concise. 
        All inputs are sanitized for security.
      </div>
    </form>
  );
} 