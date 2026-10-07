import { db } from '@/lib/db';

export const GET = async (_req: Request, { params }: { params: { id: string } }) => { // expect: endpoint/nextjs-unprotected-route
  return Response.json(await db.post.findUnique({ where: { id: params.id } }));
};

export async function DELETE(_req: Request, { params }: { params: { id: string } }) { // expect: endpoint/nextjs-unprotected-route
  await db.post.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
