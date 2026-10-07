import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() { // expect: endpoint/nextjs-unprotected-route
  return NextResponse.json(await db.user.findMany());
}

export async function POST(req: Request) { // expect: endpoint/nextjs-unprotected-route
  const body = await req.json();
  return NextResponse.json(await db.user.create({ data: body }), { status: 201 });
}
