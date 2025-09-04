"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getAllPolls, deletePoll } from "@/app/lib/actions/poll-actions";
import { useAuth } from "@/app/lib/context/auth-context";
import { useRouter } from "next/navigation";

interface Poll {
  id: string;
  question: string;
  user_id: string;
  created_at: string;
  options: string[];
}

export default function AdminPage() {
  const [polls, setPolls] = useState<Poll[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteLoading, setDeleteLoading] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();
  const router = useRouter();

  useEffect(() => {
    // Check admin status and fetch polls
    const initializeAdmin = async () => {
      if (!user) {
        router.push('/login');
        return;
      }

      try {
        const pollsResult = await getAllPolls();
        
        if (pollsResult.error) {
          if (pollsResult.error.includes('Admin privileges required')) {
            setError('Access denied: Admin privileges required');
          } else {
            setError(pollsResult.error);
          }
        } else {
          setIsAdmin(true);
          setPolls(pollsResult.polls);
        }
      } catch (error) {
        setError('Access denied: You do not have admin privileges');
      } finally {
        setLoading(false);
      }
    };

    initializeAdmin();
  }, [user, router]);

  const handleDelete = async (pollId: string) => {
    if (!confirm("Are you sure you want to delete this poll? This action cannot be undone.")) {
      return;
    }
    
    setDeleteLoading(pollId);
    const result = await deletePoll(pollId);

    if (!result.error) {
      setPolls(polls.filter((poll) => poll.id !== pollId));
    } else {
      alert(`Failed to delete poll: ${result.error}`);
    }

    setDeleteLoading(null);
  };

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p>Verifying admin access...</p>
        </div>
      </div>
    );
  }

  if (error || !isAdmin) {
    return (
      <div className="p-6 flex items-center justify-center min-h-96">
        <Card className="max-w-md w-full border-red-200 bg-red-50">
          <CardHeader>
            <CardTitle className="text-red-800">Access Denied</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-red-700 mb-4">
              {error || 'You do not have permission to access the admin panel.'}
            </p>
            <Button 
              variant="outline" 
              onClick={() => router.push('/polls')}
              className="w-full"
            >
              Return to Polls
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Admin Panel</h1>
        <p className="text-gray-600 mt-2">
          System administration - View and manage polls (Showing {polls.length} polls)
        </p>
      </div>

      <div className="grid gap-4">
        {polls.map((poll) => (
          <Card key={poll.id} className="border-l-4 border-l-blue-500">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="text-lg break-words">
                    {poll.question}
                  </CardTitle>
                  <CardDescription>
                    <div className="space-y-1 mt-2">
                      <div>
                        Created: {new Date(poll.created_at).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </div>
                      <div>Options: {poll.options.length}</div>
                    </div>
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => router.push(`/polls/${poll.id}`)}
                  >
                    View
                  </Button>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => handleDelete(poll.id)}
                    disabled={deleteLoading === poll.id}
                  >
                    {deleteLoading === poll.id ? "Deleting..." : "Delete"}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <h4 className="font-medium">Poll Options:</h4>
                <ul className="list-disc list-inside space-y-1">
                  {poll.options.slice(0, 5).map((option, index) => (
                    <li key={index} className="text-gray-700 break-words">
                      {option}
                    </li>
                  ))}
                  {poll.options.length > 5 && (
                    <li className="text-gray-500 italic">
                      ...and {poll.options.length - 5} more options
                    </li>
                  )}
                </ul>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {polls.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          No polls found in the system.
        </div>
      )}
    </div>
  );
}
