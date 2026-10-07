import { auth } from '@/auth';

export async function GET() {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  return Response.json(session.user);
}
