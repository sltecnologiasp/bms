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

    // LOGIN CLIENTE
    if (path === 'bms' && action === 'login' && method === 'POST') {
      const { code } = await request.json();
      const bms = await env.DB.prepare('SELECT code FROM bms WHERE code =?').bind(code).first();
      if (!bms) return json({ ok: false, error: 'Código inválido' });
      return json({ ok: true, token: await sign(code, env.JWT_SECRET) });
    }

    // LOGIN ADMIN
    if (path === 'bms' && action === 'admin_login' && method === 'POST') {
      const { user, password } = await request.json();
      if (user === env.ADMIN_USER && password === env.ADMIN_PASS) {
        return json({ ok: true, token: 'admin_ok' });
      }
      return json({ ok: false, error: 'Usuário ou senha inválidos' });
    }

    // DADOS CLIENTE
    if (path === 'bms' && action === 'dados' && method === 'GET') {
      const token = request.headers.get('Authorization')?.replace('Bearer ', '');
      const payload = await verify(token, env.JWT_SECRET);
      if (!payload) return json({ error: 'Invalid token' }, 401);
      const bms = await env.DB.prepare('SELECT * FROM bms WHERE code =?').bind(payload.code).first();
      if (!bms) return json({ error: 'Not found' }, 404);
      return json({
        code: bms.code,
        nome: bms.nome,
        soc: bms.soc || 0,
        voltage: bms.voltage || 0,
        current: bms.current || 0,
        temp: bms.temp || 0,
        online: bms.online || 0,
        cells: bms.cells? JSON.parse(bms.cells) : [],
        last_update: bms.last_update
      });
    }

    // AUTH ADMIN
    if (request.headers.get('Authorization')!== 'Bearer admin_ok') {
      return json({ error: 'No token' }, 401);
    }

    // CADASTRAR
    if (path === 'bms' && action === 'cadastrar' && method === 'POST') {
      const { code, nome } = await request.json();
      try {
        await env.DB.prepare('INSERT INTO bms (code, nome, created_at) VALUES (?,?, datetime("now"))').bind(code, nome).run();
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: 'BMS já cadastrada' });
      }
    }

    // LISTAR
    if (path === 'bms' && action === 'listar' && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY code').all();
      return json(results.map(r => ({...r, cells: r.cells? JSON.parse(r.cells) : [] })));
    }

    // DELETAR
    if (path === 'bms' && action === 'deletar' && method === 'DELETE') {
      const code = url.searchParams.get('code');
      await env.DB.prepare('DELETE FROM bms WHERE code =?').bind(code).run();
      return json({ ok: true });
    }

    // UPDATE - USANDO last_update
    if (path === 'bms' && action === 'update' && method === 'POST') {
      const body = await request.json();
      const { code, soc, voltage, current, temp, cells, online } = body;

      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);

      await env.DB.prepare(`
        INSERT OR REPLACE INTO bms (code, nome, soc, voltage, current, temp, cells, online, last_update, created_at)
        VALUES (
         ?,
          COALESCE((SELECT nome FROM bms WHERE code =?), ''),
         ?,?,?,?,?,?,
          datetime('now'),
          COALESCE((SELECT created_at FROM bms WHERE code =?), datetime('now'))
        )
      `).bind(
        code, code,
        Number(soc) || 0,
        Number(voltage) || 0,
        Number(current) || 0,
        Number(temp) || 0,
        JSON.stringify(cells || []),
        Number(online) || 0,
        code
      ).run();

      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);

  } catch (e) {
    return json({ ok: false, error: e.message, stack: e.stack }, 500);
  }
}

async function sign(code, secret) {
  const data = btoa(JSON.stringify({ code }));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verify(token, secret) {
  try {
    const [data] = token.split('.');
    return JSON.parse(atob(data));
  } catch { return null; }
}
