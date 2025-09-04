import { NextRequest, NextResponse } from 'next/server';
import { setCSRFToken, getClientCSRFToken } from '@/app/lib/security/csrf';

export async function GET(request: NextRequest) {
  try {
    // Generate and set CSRF token
    const token = await getClientCSRFToken();
    
    return NextResponse.json({ 
      token,
      message: 'CSRF token generated successfully' 
    });
  } catch (error) {
    console.error('CSRF token generation error:', error);
    return NextResponse.json(
      { error: 'Failed to generate CSRF token' },
      { status: 500 }
    );
  }
}

// Prevent other HTTP methods
export async function POST() {
  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  );
}

export async function PUT() {
  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  );
}

export async function DELETE() {
  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  );
}
