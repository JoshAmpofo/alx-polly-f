import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

// Define protected routes that require authentication
const PROTECTED_ROUTES = [
  '/polls',
  '/create',
  '/admin',
  '/dashboard'
];

// Define admin-only routes
const ADMIN_ROUTES = [
  '/admin'
];

// Define public routes that don't require authentication
const PUBLIC_ROUTES = [
  '/login',
  '/register',
  '/auth',
  '/',
];

export async function updateSession(request: NextRequest) {
  let supabaseResponse = NextResponse.next({
    request,
  })

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => request.cookies.set(name, value))
          supabaseResponse = NextResponse.next({
            request,
          })
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          )
        },
      },
    }
  )

  // Get user authentication status
  const {
    data: { user },
  } = await supabase.auth.getUser()

  const path = request.nextUrl.pathname;

  // Check if route is public
  const isPublicRoute = PUBLIC_ROUTES.some(route => 
    path === route || path.startsWith(route + '/')
  );

  // Check if route is protected
  const isProtectedRoute = PROTECTED_ROUTES.some(route => 
    path.startsWith(route)
  );

  // Check if route is admin-only
  const isAdminRoute = ADMIN_ROUTES.some(route => 
    path.startsWith(route)
  );

  // If user is not authenticated and trying to access protected route
  if (!user && isProtectedRoute && !isPublicRoute) {
    const url = request.nextUrl.clone()
    url.pathname = '/login'
    url.searchParams.set('redirect', path) // Store intended destination
    return NextResponse.redirect(url)
  }

  // If user is authenticated and trying to access login/register
  if (user && (path === '/login' || path === '/register')) {
    const url = request.nextUrl.clone()
    url.pathname = '/polls'
    return NextResponse.redirect(url)
  }

  // For admin routes, we'll let the page component handle authorization
  // since we need to check roles from the database
  
  // Add security headers
  supabaseResponse.headers.set('X-Frame-Options', 'DENY');
  supabaseResponse.headers.set('X-Content-Type-Options', 'nosniff');
  supabaseResponse.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  supabaseResponse.headers.set('X-XSS-Protection', '1; mode=block');
  
  // Content Security Policy
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Note: unsafe-inline/eval needed for Next.js dev
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self' https://*.supabase.co",
    "frame-ancestors 'none'"
  ].join('; ');
  
  supabaseResponse.headers.set('Content-Security-Policy', csp);

  return supabaseResponse
}