export async function onRequest({ request, env }) {
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS, PUT' };

  if (request.method === 'OPTIONS') return new Response(null, { headers });
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers });

  try {
    if (action === 'admin_login' && request.method === 'POST') {
      const { user, password } = await request.json();
      if (user === 'administrador' && password === '426240637') {
        return json({ ok: true, token: 'admin_ok' });
      }
      return json({ ok: false, error: 'Credenciais inválidas' }, 401);
    }

    if (action === 'register' && request.method === 'POST') {
      const { nome, email, senha } = await request.json();
      if (!nome ||!email || senha.length < 6) return json({ ok: false, error: 'Dados inválidos' });
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
      const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      try {
        await db.prepare('INSERT INTO users (nome,email,senha_hash) VALUES (?,?,?)').bind(nome, email, hashHex).run();
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: 'E-mail já cadastrado' }, 400);
      }
    }

    if (action === 'login_user' && request.method === 'POST') {
      const { email, senha } = await request.json();
      const { results } = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).all();
      if (!results.length) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      const user = results[0];
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
      const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (user.senha_hash!== hashHex) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      const token = Buffer.from(`user:${user.id}`).toString('base64');
      return json({ ok: true, token, nome: user.nome, email: user.email });
    }

    if (action === 'user_bms') {
      if (!token) return json({ ok: false }, 401);
      try {
        const decoded = Buffer.from(token, 'base64').toString();
        if (!decoded.startsWith('user:')) return json({ ok: false }, 401);
        const userId = parseInt(decoded.split(':')[1]);
        const { results } = await db.prepare(`
          SELECT ub.bms_code as code, ub.bms_nome as nome, b.online, b.updated_at 
          FROM user_bms ub 
          LEFT JOIN bms b ON ub.bms_code = b.code 
          WHERE ub.user_id =?
        `).bind(userId).all();
        return json(results);
      } catch(e) {
        return json({ ok: false }, 401);
      }
    }

    if (action === 'add_bms' && request.method === 'POST') {
      if (!token) return json({ ok: false }, 401);
      try {
        const decoded = Buffer.from(token, 'base64').toString();
        if (!decoded.startsWith('user:')) return json({ ok: false }, 401);
        const userId = parseInt(decoded.split(':')[1]);
        const { code, nome } = await request.json();
        if (!/^SL\d{8}$/.test(code)) return json({ ok: false, error: 'Código inválido' });
        if (!nome) return json({ ok: false, error: 'Nome obrigatório' });
        try {
          await db.prepare('INSERT INTO user_bms (user_id,bms_code,bms_nome) VALUES (?,?,?)').bind(userId, code, nome).run();
          await db.prepare('INSERT OR IGNORE INTO bms (code,nome) VALUES (?,?)').bind(code, nome).run();
          return json({ ok: true });
        } catch (e) {
          return json({ ok: false, error: 'BMS já adicionada' }, 400);
        }
      } catch(e) {
        return json({ ok: false }, 401);
      }
    }

    if (action === 'data') {
      if (!token) return json({ ok: false }, 401);
      try {
        const decoded = Buffer.from(token, 'base64').toString();
        if (!decoded.startsWith('user:')) return json({ ok: false }, 401);
        const userId = parseInt(decoded.split(':')[1]);
        const code = url.searchParams.get('code');
        const { results: check } = await db.prepare('SELECT 1 FROM user_bms WHERE user_id=? AND bms_code=?').bind(userId, code).all();
        if (!check.length) return json({ ok: false, error: 'BMS não encontrada' }, 404);
        const { results } = await db.prepare('SELECT * FROM bms WHERE code=?').bind(code).all();
        if (!results.length) return json({ ok: false, error: 'Sem dados' }, 404);
        const bms = results[0];
        bms.cells = JSON.parse(bms.cells || '[]');
        bms.online = (Date.now() - new Date(bms.updated_at).getTime()) < 10000;
        return json(bms);
      } catch(e) {
        return json({ ok: false }, 401);
      }
    }

    if (action === 'listar') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const { results } = await db.prepare('SELECT * FROM bms ORDER BY code').all();
      const parsed = results.map(b => ({...b, cells: JSON.parse(b.cells || '[]') }));
      return json(parsed);
    }

    if (action === 'cadastrar' && request.method === 'POST') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const { code, nome } = await request.json();
      try {
        await db.prepare('INSERT INTO bms (code, nome, cells) VALUES (?,?,?)').bind(code, nome || 'Sem nome', '[]').run();
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: e.message }, 400);
      }
    }

    if (action === 'deletar' && request.method === 'DELETE') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const code = url.searchParams.get('code');
      await db.prepare('DELETE FROM bms WHERE code=?').bind(code).run();
      await db.prepare('DELETE FROM user_bms WHERE bms_code=?').bind(code).run();
      return json({ ok: true });
    }

    if (action === 'listar_users') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const { results } = await db.prepare(`
        SELECT u.id, u.nome, u.email, u.created_at,
               COUNT(ub.bms_code) as total_bms
        FROM users u
        LEFT JOIN user_bms ub ON u.id = ub.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `).all();
      return json(results);
    }

    if (action === 'user_bms_admin') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const userId = url.searchParams.get('user_id');
      const { results } = await db.prepare(`
        SELECT ub.bms_code as code, ub.bms_nome as nome, b.online, b.updated_at
        FROM user_bms ub
        LEFT JOIN bms b ON ub.bms_code = b.code
        WHERE ub.user_id =?
      `).bind(userId).all();
      return json(results);
    }

    if (action === 'vincular_bms' && request.method === 'POST') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const { user_id, code, nome } = await request.json();
      if (!/^SL\d{8}$/.test(code)) return json({ ok: false, error: 'Código inválido' });
      try {
        await db.prepare('INSERT INTO user_bms (user_id,bms_code,bms_nome) VALUES (?,?,?)').bind(user_id, code, nome).run();
        await db.prepare('INSERT OR IGNORE INTO bms (code,nome) VALUES (?,?)').bind(code, nome).run();
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: 'BMS já vinculada a este usuário' }, 400);
      }
    }

    if (action === 'desvincular_bms' && request.method === 'DELETE') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const user_id = url.searchParams.get('user_id');
      const code = url.searchParams.get('code');
      await db.prepare('DELETE FROM user_bms WHERE user_id=? AND bms_code=?').bind(user_id, code).run();
      return json({ ok: true });
    }

    if (action === 'editar_nome_bms' && request.method === 'PUT') {
      if (token!== 'admin_ok') return json({ ok: false }, 401);
      const { user_id, code, nome } = await request.json();
      await db.prepare('UPDATE user_bms SET bms_nome=? WHERE user_id=? AND bms_code=?').bind(nome, user_id, code).run();
      return json({ ok: true });
    }

    if (action === 'update' && request.method === 'POST') {
      if (token!== 'bms_admin_token_426240637') return json({ ok: false, error: 'Nao autorizado' }, 401);
      const data = await request.json();
      const { code, soc, voltage, current, temp, cells } = data;
      const result = await db.prepare(`
        UPDATE bms SET soc=?, voltage=?, current=?, temp=?, cells=?, online=1, updated_at=CURRENT_TIMESTAMP 
        WHERE code=?
      `).bind(soc||0, voltage||0, current||0, temp||0, JSON.stringify(cells||[]), code).run();
      if (result.changes === 0) return json({ ok: false, error: 'BMS nao cadastrada: ' + code }, 404);
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);

  } catch (e) {
    return json({ ok: false, error: 'Erro interno: ' + e.message }, 500);
  }
}
