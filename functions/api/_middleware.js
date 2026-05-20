export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');
  const method = request.method;
  const action = url.searchParams.get('action');

  // CORS
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  const jsonResponse = (data, status = 200) => {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      }
    });
  };

  // HEALTH CHECK
  if (path === 'health' && method === 'GET') {
    try {
      await env.DB.prepare('SELECT 1').first();
      return jsonResponse({ status: 'ok', db: true });
    } catch (e) {
      return jsonResponse({ status: 'ok', db: false, error: e.message });
    }
  }

  // LOGIN CLIENTE - /api/bms?action=login
  if (path === 'bms' && action === 'login' && method === 'POST') {
    const body = await request.json();
    const bms = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(body.code).first();
    if (!bms) return jsonResponse({ ok: false, error: 'Código inválido' });
    
    const token = await signJWT({ code: body.code }, env.JWT_SECRET);
    return jsonResponse({ ok: true, token });
  }

  // LOGIN ADMIN - /api/bms?action=admin_login
  if (path === 'bms' && action === 'admin_login' && method === 'POST') {
    const body = await request.json();
    if (body.user === env.ADMIN_USER && body.password === env.ADMIN_PASS) {
      return jsonResponse({ ok: true, token: 'admin_ok' });
    }
    return jsonResponse({ ok: false, error: 'Usuário ou senha inválidos' });
  }

  // DADOS CLIENTE - /api/bms?action=dados
  if (path === 'bms' && action === 'dados' && method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (!auth) return jsonResponse({ error: 'No token' }, 401);
    
    const token = auth.replace('Bearer ', '');
    const payload = await verifyJWT(token, env.JWT_SECRET);
    if (!payload) return jsonResponse({ error: 'Invalid token' }, 401);

    const bms = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(payload.code).first();
    if (!bms) return jsonResponse({ error: 'Not found' }, 404);
    
    return jsonResponse({
      code: bms.code,
      nome: bms.nome,
      soc: bms.soc,
      voltage: bms.voltage,
      current: bms.current,
      temp: bms.temp,
      online: bms.online,
      cells: bms.cells ? JSON.parse(bms.cells) : []
    });
  }

  // AUTH ADMIN
  const auth = request.headers.get('Authorization');
  if (!auth || auth !== 'Bearer admin_ok') {
    return jsonResponse({ error: 'No token' }, 401);
  }

  // CADASTRAR - /api/bms?action=cadastrar
  if (path === 'bms' && action === 'cadastrar' && method === 'POST') {
    const body = await request.json();
    try {
      await env.DB.prepare('INSERT INTO bms (code, nome) VALUES (?, ?)').bind(body.code, body.nome).run();
      return jsonResponse({ ok: true });
    } catch (e) {
      return jsonResponse({ ok: false, error: 'BMS já cadastrada' });
    }
  }

  // LISTAR - /api/bms?action=listar
  if (path === 'bms' && action === 'listar' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY code').all();
    const bms = results.map(r => ({
      ...r,
      cells: r.cells ? JSON.parse(r.cells) : []
    }));
    return jsonResponse(bms);
  }

  // DELETAR - /api/bms?action=deletar
  if (path === 'bms' && action === 'deletar' && method === 'DELETE') {
    const code = url.searchParams.get('code');
    await env.DB.prepare('DELETE FROM bms WHERE code = ?').bind(code).run();
    return jsonResponse({ ok: true });
  }

  // ATUALIZAR BMS - /api/bms?action=update
  if (path === 'bms' && action === 'update' && method === 'POST') {
    const body = await request.json();
    await env.DB.prepare(`
      UPDATE bms SET 
        soc=?, voltage=?, current=?, temp=?, 
        cells=?, online=?, updated_at=datetime('now') 
      WHERE code=?
    `).bind(
      body.soc, body.voltage, body.current, body.temp,
      JSON.stringify(body.cells), body.online, body.code
    ).run();
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const data = `${encodedHeader}.${encodedPayload}`;
  
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  
  return `${data}.${encodedSignature}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = `${header}.${payload}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const signatureBytes = Uint8Array.from(atob(signature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (e) {
    return null;
  }
}
