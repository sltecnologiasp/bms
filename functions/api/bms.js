export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const auth = request.headers.get('Authorization');
  
  if (auth !== 'Bearer admin_ok') {
    return Response.json({ok: false, error: 'Unauthorized'}, {status: 401});
  }

  if (!env.DB) {
    return Response.json({ok: false, error: 'D1 binding DB não encontrado'});
  }

  const db = env.DB;

  if (request.method === 'POST' && action === 'cadastrar') {
    const { code } = await request.json();
    
    const existing = await db.prepare('SELECT code FROM bms WHERE code = ?').bind(code).first();
    
    // DEBUG: Retorna o que veio pra gente ver
    return Response.json({
      ok: false, 
      debug: 'teste',
      existing: existing,
      tipo: typeof existing,
      is_null: existing === null,
      keys: existing ? Object.keys(existing) : null,
      stringify: JSON.stringify(existing)
    });
  }

  if (request.method === 'GET' && action === 'listar') {
    const { results } = await db.prepare('SELECT * FROM bms').all();
    return Response.json({ok: true, bms: results});
  }

  return Response.json({ok: false, error: 'Action inválida'});
}
