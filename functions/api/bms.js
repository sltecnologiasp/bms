export async function onRequest(context) {
  const { request, env } = context;
  const { code } = await request.json();
  const db = env.DB;
  
  const { results, success, meta } = await db.prepare('SELECT code FROM bms WHERE code = ?').bind(code).all();
  
  return Response.json({
    ok: false,
    debug: true,
    code_enviado: code,
    results: results,
    length: results.length,
    success: success,
    meta: meta
  });
}
