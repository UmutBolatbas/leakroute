// Private folders are not routable in Next.js.
export async function POST() {
  return Response.json({});
}
