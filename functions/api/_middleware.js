export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');
  const method = request.method;

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

  // LOGIN
  if (path === 'login' && method === 'POST') {
    const body = await request.json();
    if (body.user === env.ADMIN_USER && body.pass === env.ADMIN_PASS) {
      const token = await signJWT({ user: body.user }, env.JWT_SECRET);
      return jsonResponse({ success: true, token });
    }
    return jsonResponse({ success: false, error: 'Unauthorized' }, 401);
  }

  // AUTH MIDDLEWARE
  const auth = request.headers.get('Authorization');
  if (!auth) return jsonResponse({ error: 'No token' }, 401);
  
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return jsonResponse({ error: 'Invalid token' }, 401);

  // GET BMS
  if (path === 'bms' && method === 'GET') {
    const code = url.searchParams.get('code');
    if (!code) return jsonResponse({ error: 'Missing code' }, 400);
    
    const data = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
    if (!data) return jsonResponse({ error: 'Not found' }, 404);
    
    return jsonResponse(data);
  }

  // UPDATE BMS
  if (path === 'bms' && method === 'PUT') {
    const body = await request.json();
    await env.DB.prepare(`
      UPDATE bms SET 
        status=?, responsible=?, diagnosis=?, 
        solution=?, history=?, updated_at=datetime('now') 
      WHERE code=?
    `).bind(
      body.status, body.responsible, body.diagnosis, 
      body.solution, JSON.stringify(body.history), body.code
    ).run();
    
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: 'Not found' }, 404);
}

async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  const data = `${encodedHeader}.${encodedPayload}`;
  
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${data}.${encodedSignature}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const data = `${header}.${payload}`;
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureBytes = Uint8Array.from(
      atob(signature.replace(/-/g, '+').replace(/_/g, '/')), 
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(data));
    
    if (!valid) return null;
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (e) {
    return null;
  }
}
