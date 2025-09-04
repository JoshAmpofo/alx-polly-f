"use client";

import Link from "next/link";
import { useState } from "react";
import { useAuth } from "@/app/lib/context/auth-context";
import { Button } from "@/components/ui/button";
import { deletePoll } from "@/app/lib/actions/poll-actions";
import { sanitizeText } from "@/app/lib/utils/sanitizer";

interface Poll {
  id: string;
  question: string;
  options: any[];
  user_id: string;
}

interface PollActionsProps {
  poll: Poll;
}

export default function PollActions({ poll }: PollActionsProps) {
  const { user } = useAuth();
  const [isDeleting, setIsDeleting] = useState(false);
  
  const handleDelete = async () => {
    if (!confirm("Are you sure you want to delete this poll? This action cannot be undone.")) {
      return;
    }
    
    setIsDeleting(true);
    
    try {
      // Create a form data with CSRF token
      const formData = new FormData();
      
      // Get CSRF token
      const response = await fetch('/api/csrf-token');
      const data = await response.json();
      formData.append('csrf-token', data.token);
      
      const result = await deletePoll(poll.id, formData);
      
      if (result.error) {
        alert(`Failed to delete poll: ${result.error}`);
      } else {
        // Refresh the page to update the poll list
        window.location.reload();
      }
    } catch (error) {
      alert("Failed to delete poll. Please try again.");
    } finally {
      setIsDeleting(false);
    }
  };

  // Sanitize poll question for display
  const sanitizedQuestion = sanitizeText(poll.question);
  
  // Check if current user owns this poll
  const isOwner = user && user.id === poll.user_id;

  return (
    <div className="border rounded-md shadow-md hover:shadow-lg transition-shadow bg-white">
      <Link href={`/polls/${poll.id}`}>
        <div className="group p-4">
          <div className="h-full">
            <div>
              <h2 className="group-hover:text-blue-600 transition-colors font-bold text-lg break-words">
                {sanitizedQuestion}
              </h2>
              <p className="text-slate-500">
                {poll.options?.length || 0} options
              </p>
            </div>
          </div>
        </div>
      </Link>
      
      {/* Only show edit/delete buttons to poll owner */}
      {isOwner && (
        <div className="flex gap-2 p-2 border-t">
          <Button asChild variant="outline" size="sm" disabled={isDeleting}>
            <Link href={`/polls/${poll.id}/edit`}>
              Edit Poll
            </Link>
          </Button>
          <Button 
            variant="destructive" 
            size="sm" 
            onClick={handleDelete}
            disabled={isDeleting}
          >
            {isDeleting ? "Deleting..." : "Delete"}
          </Button>
        </div>
      )}
      
      {/* Show ownership info for debugging (remove in production) */}
      {process.env.NODE_ENV === 'development' && (
        <div className="text-xs text-gray-400 p-2 border-t">
          Owner: {poll.user_id === user?.id ? 'You' : 'Other user'}
        </div>
      )}
    </div>
  );
}
