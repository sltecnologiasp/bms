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

    // LOGIN ADMIN - ADICIONADO DE VOLTA
    if (path === 'bms' && action === 'admin_login' && method === 'POST') {
      const { user, password } = await request.json();
      // Muda aqui pra tua senha. Por enquanto: admin / 1234
      if (user === 'admin' && password === '1234') {
        return json({ ok: true, token: 'admin_ok' });
      }
      return json({ ok: false, error: 'Usuário ou senha inválidos' });
    }

    // LOGIN CLIENTE
    if (path === 'bms' && action === 'login' && method === 'POST') {
      const { code } = await request.json();
      const bms = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
      if (!bms) return json({ ok: false, error: 'BMS não encontrada' });
      const token = btoa(JSON.stringify({ code }));
      return json({ ok: true, token, bms: {...bms, cells: bms.cells ? JSON.parse(bms.cells) : []} });
    }

    // DADOS CLIENTE
    if (path === 'bms' && action === 'dados' && method === 'GET') {
      const token = request.headers.get('Authorization')?.replace('Bearer ', '');
      if (!token || token === 'admin_ok') return json({ ok: false, error: 'Token de cliente obrigatório' }, 401);
      try {
        const { code } = JSON.parse(atob(token));
        const bms = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
        if (!bms) return json({ ok: false, error: 'BMS não encontrada' }, 404);
        return json({ ok: true, bms: {...bms, cells: bms.cells ? JSON.parse(bms.cells) : []} });
      } catch {
        return json({ ok: false, error: 'Token inválido' }, 401);
      }
    }

    // UPDATE TELEMETRIA - SEM AUTH
    if (path === 'bms' && action === 'update' && method === 'POST') {
      const body = await request.json();
      const { code, soc, voltage, current, temp, cells, online } = body;
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      const result = await env.DB.prepare(`
        UPDATE bms SET soc = ?, voltage = ?, current = ?, temp = ?, 
        cells = ?, online = ?, last_update = ? WHERE code = ?
      `).bind(
        Number(soc) || 0, Number(voltage) || 0, Number(current) || 0, Number(temp) || 0,
        JSON.stringify(cells || []), Number(online) || 0, Date.now(), code
      ).run();
      if (result.meta.changes === 0) return json({ ok: false, error: 'BMS não encontrada' }, 404);
      return json({ ok: true });
    }

    // AUTH ADMIN - DAQUI PRA BAIXO PRECISA DO TOKEN
    if (request.headers.get('Authorization') !== 'Bearer admin_ok') {
      return json({ error: 'Unauthorized' }, 401);
    }

    // CADASTRAR
    if (path === 'bms' && action === 'cadastrar' && method === 'POST') {
      const { code, nome } = await request.json();
      if (!code || !code.startsWith('SL') || code.length !== 10) {
        return json({ ok: false, error: 'Código inválido' });
      }
      const count = await env.DB.prepare('SELECT COUNT(*) as total FROM bms WHERE code = ?').bind(code).first();
      if (count.total > 0) return json({ ok: false, error: 'BMS já cadastrada' });
      await env.DB.prepare('INSERT INTO bms (code, nome, created_at) VALUES (?, ?, ?)').bind(code, nome || '', Date.now()).run();
      return json({ ok: true });
    }

    // LISTAR
    if (path === 'bms' && action === 'listar' && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY created_at DESC').all();
      return json({ ok: true, bms: results.map(r => ({...r, cells: r.cells ? JSON.parse(r.cells) : []})) });
    }

    // DELETAR
    if (path === 'bms' && action === 'deletar' && method === 'DELETE') {
      const code = url.searchParams.get('code');
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      await env.DB.prepare('DELETE FROM bms WHERE code = ?').bind(code).run();
      return json({ ok: true });
    }

    // EDITAR
    if (path === 'bms' && action === 'editar' && method === 'POST') {
      const { code, nome } = await request.json();
      await env.DB.prepare('UPDATE bms SET nome = ? WHERE code = ?').bind(nome, code).run();
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
