export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const auth = request.headers.get('Authorization');
  
  if (auth !== 'Bearer admin_ok') {
    return Response.json({ok: false, error: 'Unauthorized'}, {status: 401});
  }

  const db = env.DB;

  try {
    if (request.method === 'POST' && action === 'cadastrar') {
      const { code } = await request.json();
      if (!code || !code.startsWith('SL') || code.length !== 10) {
        return Response.json({ok: false, error: 'Código inválido'});
      }
      
      const existing = await db.prepare('SELECT code FROM bms WHERE code = ?').bind(code).first();
      if (existing !== null) {
        return Response.json({ok: false, error: 'BMS já cadastrada'});
      }
      
      await db.prepare('INSERT INTO bms (code, created_at) VALUES (?, ?)').bind(code, Date.now()).run();
      return Response.json({ok: true});
    }

    if (request.method === 'GET' && action === 'listar') {
      const { results } = await db.prepare('SELECT * FROM bms ORDER BY created_at DESC').all();
      return Response.json({ok: true, bms: results || []});
    }

    if (request.method === 'GET' && action === 'get') {
      const code = url.searchParams.get('code');
      const bms = await db.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
      if (!bms) return Response.json({ok: false, error: 'BMS não encontrada'});
      return Response.json({ok: true, bms});
    }

    if (request.method === 'POST' && action === 'deletar') {
      const { code } = await request.json();
      await db.prepare('DELETE FROM bms WHERE code = ?').bind(code).run();
      return Response.json({ok: true});
    }

    return Response.json({ok: false, error: 'Action inválida'});
  } catch (e) {
    return Response.json({ok: false, error: e.message}, {status: 500});
  }
}
