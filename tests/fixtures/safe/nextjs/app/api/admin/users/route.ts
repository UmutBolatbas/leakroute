// Covered by middleware.ts (matcher '/api/admin/:path*').
export async function DELETE() {
  return new Response(null, { status: 204 });
}
