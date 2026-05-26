export async function onRequest({ request, env }) {
  const db = env.DB;
  if (!db) return new Response(JSON.stringify({ ok: false, error: 'D1 não conectado' }), { status: 500 });

  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS' };

  if (request.method === 'OPTIONS') return new Response(null, { headers });
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers });

  try {
    // REGISTER
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

    // LOGIN
    if (action === 'login_user' && request.method === 'POST') {
      const { email, senha } = await request.json();
      const { results } = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).all();
      if (!results.length) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      const user = results[0];
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
      const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (user.senha_hash!== hashHex) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      const token = btoa(`user:${user.id}`);
      return json({ ok: true, token, nome: user.nome, email: user.email });
    }

    // LISTAR BMS
    if (action === 'user_bms') {
      if (!token ||!token.startsWith('dXNlcjo')) return json({ ok: false }, 401);
      const userId = parseInt(atob(token).split(':')[1]);
      const { results } = await db.prepare(`SELECT ub.bms_code as code, ub.bms_nome as nome, b.online, b.updated_at FROM user_bms ub LEFT JOIN bms b ON ub.bms_code = b.code WHERE ub.user_id =?`).bind(userId).all();
      return json(results);
    }

    // ADD BMS
    if (action === 'add_bms' && request.method === 'POST') {
      if (!token ||!token.startsWith('dXNlcjo')) return json({ ok: false }, 401);
      const userId = parseInt(atob(token).split(':')[1]);
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
    }

    // DADOS BMS
    if (action === 'data') {
      if (!token ||!token.startsWith('dXNlcjo')) return json({ ok: false }, 401);
      const userId = parseInt(atob(token).split(':')[1]);
      const code = url.searchParams.get('code');
      const { results: check } = await db.prepare('SELECT 1 FROM user_bms WHERE user_id=? AND bms_code=?').bind(userId, code).all();
      if (!check.length) return json({ ok: false, error: 'BMS não encontrada' }, 404);
      const { results } = await db.prepare('SELECT * FROM bms WHERE code=?').bind(code).all();
      if (!results.length) return json({ ok: false, error: 'Sem dados' }, 404);
      const bms = results[0];
      bms.cells = JSON.parse(bms.cells || '[]');
      bms.online = (Date.now() - new Date(bms.updated_at).getTime()) < 10000;
      return json(bms);
    }

    // UPDATE ESP32
    if (action === 'update' && request.method === 'POST') {
      if (token!== 'bms_admin_token_426240637') return json({ ok: false, error: 'Nao autorizado' }, 401);
      const data = await request.json();
      const { code, soc, voltage, current, temp, cells } = data;
      const result = await db.prepare(`UPDATE bms SET soc=?, voltage=?, current=?, temp=?, cells=?, online=1, updated_at=CURRENT_TIMESTAMP WHERE code=?`).bind(soc||0, voltage||0, current||0, temp||0, JSON.stringify(cells||[]), code).run();
      if (result.changes === 0) return json({ ok: false, error: 'BMS nao cadastrada: ' + code }, 404);
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ ok: false, error: 'Erro interno: ' + e.message }, 500);
  }
}
