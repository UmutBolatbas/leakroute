import { NextResponse, type NextRequest } from 'next/server';

// Only page routes are guarded; API routes fall through.
const protectedRoutes = ['/dashboard', '/settings'];

export function middleware(req: NextRequest) {
  const token = req.cookies.get('session');
  if (protectedRoutes.some((r) => req.nextUrl.pathname.startsWith(r)) && !token) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
