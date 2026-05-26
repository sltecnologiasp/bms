export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
  
  if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
  
  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' }
  });

  const genToken = (id) => btoa(`user:${id}:${Date.now()}`);
  
  const parseToken = (auth) => {
    if (!auth?.startsWith('Bearer ')) return null;
    const token = auth.slice(7);
    if (token === 'admin_ok') return { type: 'admin' };
    try {
      const decoded = atob(token);
      const [type, id] = decoded.split(':');
      return type === 'user' ? { type: 'user', id: parseInt(id) } : null;
    } catch { return null; }
  };

  const hashPassword = async (senha) => {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  try {
    // REGISTER
    if (action === 'register' && request.method === 'POST') {
      const { nome, email, senha } = await request.json();
      if (!nome || !email || !senha) return json({ ok: false, error: 'Dados inválidos' }, 400);
      
      const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (exists) return json({ ok: false, error: 'E-mail já cadastrado' }, 400);
      
      const senha_hash = await hashPassword(senha);
      await env.DB.prepare('INSERT INTO users (nome, email, senha_hash) VALUES (?, ?, ?)')
        .bind(nome, email, senha_hash).run();
      
      return json({ ok: true });
    }

    // LOGIN USER
    if (action === 'login_user' && request.method === 'POST') {
      const { email, senha } = await request.json();
      const senha_hash = await hashPassword(senha);
      
      const user = await env.DB.prepare('SELECT id, nome, email FROM users WHERE email = ? AND senha_hash = ?')
        .bind(email, senha_hash).first();
      
      if (!user) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      
      return json({ ok: true, token: genToken(user.id), nome: user.nome, email: user.email });
    }

    // LOGIN ADMIN
    if (action === 'login_admin' && request.method === 'POST') {
      const { user, password } = await request.json();
      if (user === 'administrador' && password === '426240637') {
        return json({ ok: true, token: 'admin_ok' });
      }
      return json({ ok: false, error: 'Credenciais inválidas' }, 401);
    }

    // AUTH CHECK
    const auth = request.headers.get('Authorization');
    const authData = parseToken(auth);
    
    if (!authData && !['login_user', 'register', 'login_admin', 'update'].includes(action)) {
      return json({ ok: false, error: 'Não autorizado' }, 401);
    }

    const userId = authData?.type === 'user' ? authData.id : null;
    const isAdmin = authData?.type === 'admin';

    // ADD BMS - USER
    if (action === 'add_bms' && request.method === 'POST') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const { code, nome } = await request.json();
      if (!code?.startsWith('SL') || code.length !== 10) return json({ ok: false, error: 'Código inválido. Use SL + 8 números' }, 400);
      
      await env.DB.prepare('INSERT OR IGNORE INTO user_bms (user_id, bms_code, bms_nome) VALUES (?, ?, ?)')
        .bind(userId, code, nome || code).run();
      await env.DB.prepare('INSERT OR IGNORE INTO bms (code, nome) VALUES (?, ?)')
        .bind(code, nome || code).run();
      
      return json({ ok: true });
    }

    // LIST USER BMS
    if (action === 'user_bms' && request.method === 'GET') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const { results } = await env.DB.prepare(`
        SELECT ub.bms_code as code, ub.bms_nome as nome, b.online, b.updated_at, b.soc, b.voltage, b.current, b.temp, b.cells
        FROM user_bms ub
        LEFT JOIN bms b ON b.code = ub.bms_code
        WHERE ub.user_id = ?
        ORDER BY ub.created_at DESC
      `).bind(userId).all();
      return json((results || []).map(r=>({...r,cells:JSON.parse(r.cells||'[]')})));
    }

    // LIST ALL BMS - ADMIN
    if (action === 'all_bms' && request.method === 'GET') {
      if (!isAdmin) return json({ ok: false, error: 'Admin only' }, 403);
      const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY updated_at DESC').all();
      return json((results || []).map(r=>({...r,cells:JSON.parse(r.cells||'[]')})));
    }

    // LIST ALL USERS - ADMIN
    if (action === 'all_users' && request.method === 'GET') {
      if (!isAdmin) return json({ ok: false, error: 'Admin only' }, 403);
      const { results } = await env.DB.prepare(`
        SELECT u.id, u.nome, u.email, u.created_at,
          COUNT(ub.id) as bms_count
        FROM users u
        LEFT JOIN user_bms ub ON ub.user_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `).all();
      return json(results || []);
    }

    // DATA BMS
    if (action === 'data' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      
      if (userId && !isAdmin) {
        const check = await env.DB.prepare('SELECT id FROM user_bms WHERE user_id = ? AND bms_code = ?')
          .bind(userId, code).first();
        if (!check) return json({ ok: false, error: 'Acesso negado' }, 403);
      }
      
      const data = await env.DB.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
      if (!data) return json({ ok: false, error: 'BMS não encontrada' }, 404);
      
      const online = data.online && (Date.now() - new Date(data.updated_at).getTime() < 10000);
      return json({
        ...data,
        online,
        cells: JSON.parse(data.cells || '[]')
      });
    }

    // UPDATE BMS DATA - ESP32
    if (action === 'update' && request.method === 'POST') {
      const { code, soc, voltage, current, temp, cells } = await request.json();
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      
      await env.DB.prepare(`
        INSERT INTO bms (code, soc, voltage, current, temp, cells, online, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(code) DO UPDATE SET
          soc = excluded.soc,
          voltage = excluded.voltage,
          current = excluded.current,
          temp = excluded.temp,
          cells = excluded.cells,
          online = 1,
          updated_at = CURRENT_TIMESTAMP
      `).bind(
        code, soc || 0, voltage || 0, current || 0, temp || 0,
        JSON.stringify(cells || [])
      ).run();
      
      return json({ ok: true });
    }

    // DELETAR BMS - ADMIN
    if (action === 'deletar' && request.method === 'DELETE') {
      if (!isAdmin) return json({ ok: false, error: 'Admin only' }, 403);
      const code = url.searchParams.get('code');
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      await env.DB.prepare('DELETE FROM bms WHERE code = ?').bind(code).run();
      await env.DB.prepare('DELETE FROM user_bms WHERE bms_code = ?').bind(code).run();
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
    
  } catch (e) {
    return json({ ok: false, error: 'Erro interno: ' + e.message }, 500);
  }
}
    // EDITAR USER - ADMIN
    if (action === 'edit_user' && request.method === 'POST') {
      if (!isAdmin) return json({ ok: false, error: 'Admin only' }, 403);
      const { id, nome, email } = await request.json();
      if (!id || !nome || !email) return json({ ok: false, error: 'Dados inválidos' }, 400);
      
      await env.DB.prepare('UPDATE users SET nome = ?, email = ? WHERE id = ?')
        .bind(nome, email, id).run();
      return json({ ok: true });
    }

    // DELETAR USER - ADMIN
    if (action === 'delete_user' && request.method === 'DELETE') {
      if (!isAdmin) return json({ ok: false, error: 'Admin only' }, 403);
      const id = url.searchParams.get('id');
      if (!id) return json({ ok: false, error: 'ID obrigatório' }, 400);
      
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
      await env.DB.prepare('DELETE FROM user_bms WHERE user_id = ?').bind(id).run();
      return json({ ok: true });
    }
