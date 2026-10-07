import { requireUser } from '@/lib/session';

export async function POST(req: Request) {
  const user = await requireUser();
  return Response.json({ owner: user, ...(await req.json()) }, { status: 201 });
}
