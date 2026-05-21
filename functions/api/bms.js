export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const headers = { 
    'Content-Type': 'application/json', 
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  if (action === 'admin_login' && request.method === 'POST') {
    const { user, password } = await request.json();
    if (user === 'admin' && password === 'admin123') {
      return new Response(JSON.stringify({ ok: true, token: 'admin_ok' }), { headers });
    }
    return new Response(JSON.stringify({ ok: false, error: 'Credenciais inválidas' }), { status: 401, headers });
  }

  if (action === 'login' && request.method === 'POST') {
    const { code } = await request.json();
    const { results } = await db.prepare('SELECT * FROM bms WHERE code =?').bind(code).all();
    if (results.length === 0) return new Response(JSON.stringify({ ok: false, error: 'BMS não encontrada' }), { status: 404, headers });
    return new Response(JSON.stringify({ ok: true, token: btoa(code) }), { headers });
  }

  if (action === 'data') {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    const code = atob(token || '');
    const { results } = await db.prepare('SELECT * FROM bms WHERE code =?').bind(code).all();
    if (results.length === 0) return new Response(JSON.stringify({ ok: false }), { status: 404, headers });
    const bms = results[0];
    bms.cells = JSON.parse(bms.cells || '[]');
    return new Response(JSON.stringify(bms), { headers });
  }

  if (action === 'listar') {
    const auth = request.headers.get('Authorization');
    if (auth!== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const { results } = await db.prepare('SELECT * FROM bms ORDER BY code').all();
    const parsed = results.map(b => ({...b, cells: JSON.parse(b.cells || '[]') }));
    return new Response(JSON.stringify(parsed), { headers });
  }

  if (action === 'cadastrar' && request.method === 'POST') {
    const auth = request.headers.get('Authorization');
    if (auth!== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const { code, nome } = await request.json();
    try {
      await db.prepare('INSERT INTO bms (code, nome, cells) VALUES (?,?,?)').bind(code, nome || 'Sem nome', '[]').run();
      return new Response(JSON.stringify({ ok: true }), { headers });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 400, headers });
    }
  }

  if (action === 'deletar' && request.method === 'DELETE') {
    const auth = request.headers.get('Authorization');
    if (auth!== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const code = url.searchParams.get('code');
    await db.prepare('DELETE FROM bms WHERE code =?').bind(code).run();
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (action === 'update' && request.method === 'POST') {
    const data = await request.json();
    const { code, soc, voltage, current, temp, online, cells } = data;
    await db.prepare(`UPDATE bms SET soc=?, voltage=?, current=?, temp=?, online=?, cells=?, updated_at=CURRENT_TIMESTAMP WHERE code=?`)
   .bind(soc, voltage, current, temp, online? 1 : 0, JSON.stringify(cells || []), code).run();
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
}
