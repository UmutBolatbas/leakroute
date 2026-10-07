import { withAuth } from '@/lib/with-auth';

export const POST = withAuth(async (req: Request) => Response.json(await req.json()));
