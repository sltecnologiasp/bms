export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');
  const method = request.method;
  const action = url.searchParams.get('action');

  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });

  try {
    // HEALTH
    if (path === 'health' && method === 'GET') {
      await env.DB.prepare('SELECT 1').first();
      return json({ status: 'ok', db: true });
    }

    // AUTH ADMIN
    if (request.headers.get('Authorization') !== 'Bearer admin_ok') {
      return json({ error: 'Unauthorized' }, 401);
    }

    // CADASTRAR - CORRIGIDO PRA TUA TABELA
    if (path === 'bms' && action === 'cadastrar' && method === 'POST') {
      const { code } = await request.json();
      if (!code || !code.startsWith('SL') || code.length !== 10) {
        return json({ ok: false, error: 'Código inválido' });
      }
      
      const count = await env.DB.prepare('SELECT COUNT(*) as total FROM bms WHERE code = ?').bind(code).first();
      if (count.total > 0) {
        return json({ ok: false, error: 'BMS já cadastrada' });
      }
      
      await env.DB.prepare('INSERT INTO bms (code, created_at) VALUES (?, ?)').bind(code, Date.now()).run();
      return json({ ok: true });
    }

    // LISTAR - CORRIGIDO
    if (path === 'bms' && action === 'listar' && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY created_at DESC').all();
      return json({ ok: true, bms: results });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
