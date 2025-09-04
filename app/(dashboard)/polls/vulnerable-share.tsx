"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Copy, Share2, Twitter, Facebook, Mail } from "lucide-react";
import { toast } from "sonner";
import { escapeForUrl, sanitizeText } from "@/app/lib/utils/sanitizer";

interface SecureShareProps {
  pollId: string;
  pollTitle: string;
}

export default function SecureShare({
  pollId,
  pollTitle,
}: SecureShareProps) {
  const [shareUrl, setShareUrl] = useState("");
  const [sanitizedTitle, setSanitizedTitle] = useState("");

  useEffect(() => {
    // Sanitize the poll title
    const cleanTitle = sanitizeText(pollTitle);
    setSanitizedTitle(cleanTitle);
    
    // Generate the share URL with validated poll ID
    if (pollId && typeof pollId === 'string' && pollId.length > 0) {
      const baseUrl = window.location.origin;
      const pollUrl = `${baseUrl}/polls/${encodeURIComponent(pollId)}`;
      setShareUrl(pollUrl);
    }
  }, [pollId, pollTitle]);

  const copyToClipboard = async () => {
    try {
      if (!shareUrl) {
        toast.error("Share URL not available");
        return;
      }
      
      await navigator.clipboard.writeText(shareUrl);
      toast.success("Link copied to clipboard!");
    } catch (err) {
      toast.error("Failed to copy link");
    }
  };

  const shareOnTwitter = () => {
    if (!shareUrl || !sanitizedTitle) {
      toast.error("Cannot share: invalid data");
      return;
    }
    
    const text = escapeForUrl(`Check out this poll: ${sanitizedTitle.slice(0, 100)}`);
    const url = encodeURIComponent(shareUrl);
    
    const twitterUrl = `https://twitter.com/intent/tweet?text=${text}&url=${url}`;
    
    try {
      window.open(twitterUrl, "_blank", "noopener,noreferrer");
    } catch (error) {
      toast.error("Failed to open Twitter");
    }
  };

  const shareOnFacebook = () => {
    if (!shareUrl) {
      toast.error("Cannot share: invalid URL");
      return;
    }
    
    const url = encodeURIComponent(shareUrl);
    const facebookUrl = `https://www.facebook.com/sharer/sharer.php?u=${url}`;
    
    try {
      window.open(facebookUrl, "_blank", "noopener,noreferrer");
    } catch (error) {
      toast.error("Failed to open Facebook");
    }
  };

  const shareViaEmail = () => {
    if (!shareUrl || !sanitizedTitle) {
      toast.error("Cannot share: invalid data");
      return;
    }
    
    const subject = escapeForUrl(`Poll: ${sanitizedTitle.slice(0, 50)}`);
    const body = escapeForUrl(
      `Hi! I'd like to share this poll with you: ${shareUrl}`
    );
    
    const emailUrl = `mailto:?subject=${subject}&body=${body}`;
    
    try {
      window.open(emailUrl, "_self");
    } catch (error) {
      toast.error("Failed to open email client");
    }
  };

  // Don't render if essential data is missing
  if (!pollId || !sanitizedTitle || !shareUrl) {
    return (
      <Card className="w-full max-w-2xl">
        <CardContent className="p-6">
          <p className="text-gray-500">Share options not available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-2xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Share2 className="h-5 w-5" />
          Share This Poll
        </CardTitle>
        <CardDescription>
          Share your poll with others to gather votes.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* URL Display */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-700">
            Shareable Link
          </label>
          <div className="flex space-x-2">
            <Input
              value={shareUrl}
              readOnly
              className="font-mono text-sm"
              placeholder="Generating link..."
            />
            <Button onClick={copyToClipboard} variant="outline" size="sm">
              <Copy className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Social Sharing Buttons */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-700">
            Share on social media
          </label>
          <div className="flex space-x-2">
            <Button
              onClick={shareOnTwitter}
              variant="outline"
              size="sm"
              className="flex items-center gap-2"
            >
              <Twitter className="h-4 w-4" />
              Twitter
            </Button>
            <Button
              onClick={shareOnFacebook}
              variant="outline"
              size="sm"
              className="flex items-center gap-2"
            >
              <Facebook className="h-4 w-4" />
              Facebook
            </Button>
            <Button
              onClick={shareViaEmail}
              variant="outline"
              size="sm"
              className="flex items-center gap-2"
            >
              <Mail className="h-4 w-4" />
              Email
            </Button>
          </div>
        </div>
        
        {/* Security Notice */}
        <div className="text-xs text-gray-500 mt-4 p-3 bg-gray-50 rounded">
          <strong>Privacy:</strong> This sharing feature does not track or store your social media interactions.
        </div>
      </CardContent>
    </Card>
  );
}
