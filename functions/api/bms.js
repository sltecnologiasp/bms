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
    if (!code || !code.startsWith('SL') || code.length !== 10) {
      return Response.json({ok: false, error: 'Código inválido'});
    }
    
    const existing = await db.prepare('SELECT code FROM bms WHERE code = ?').bind(code).first();
    
    // FIX: Checa se tem .code dentro, não só se existing existe
    if (existing && existing.code) {
      return Response.json({ok: false, error: 'BMS já cadastrada'});
    }
    
    await db.prepare('INSERT INTO bms (code, created_at) VALUES (?, ?)').bind(code, Date.now()).run();
    return Response.json({ok: true});
  }

  if (request.method === 'GET' && action === 'listar') {
    const { results } = await db.prepare('SELECT * FROM bms ORDER BY created_at DESC').all();
    return Response.json({ok: true, bms: results || []});
  }

  return Response.json({ok: false, error: 'Action inválida'});
}
