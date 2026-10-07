import { clerkMiddleware } from '@clerk/nextjs/server';

// clerkMiddleware() alone only attaches auth state; it does not block anything.
export default clerkMiddleware();

export const config = {
  matcher: ['/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico)).*)', '/(api|trpc)(.*)'],
};
