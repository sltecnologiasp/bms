export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const DB = env.DB;
  
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  const action = url.searchParams.get('action');
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');

  function genToken(userId) {
    return btoa(JSON.stringify({ id: userId, t: Date.now() }));
  }

  function verifyToken(t) {
    try {
      const data = JSON.parse(atob(t));
      return data.id;
    } catch {
      return null;
    }
  }

  function genCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  async function sendEmail(to, code) {
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer re_SHXjFUEc_Po2o2ftMykF5ce4UAA4tqvso',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: 'SMART BMS <onboarding@resend.dev>',
          to: to,
          subject: 'Código de confirmação - SMART BMS',
          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#05070d;color:#fff;padding:40px;border-radius:16px">
              <h1 style="color:#00ffff;text-align:center;margin-bottom:30px">SMART BMS</h1>
              <h2 style="text-align:center;font-size:36px;letter-spacing:12px;color:#00ff88;margin:20px 0">${code}</h2>
              <p style="text-align:center;opacity:.8;font-size:16px">Use este código para confirmar seu email.</p>
              <p style="text-align:center;opacity:.6;font-size:14px;margin-top:20px">Expira em 15 minutos.</p>
              <p style="text-align:center;opacity:.4;font-size:12px;margin-top:40px">Se você não solicitou este código, ignore este email.</p>
            </div>
          `
        })
      });
      return res.ok;
    } catch (e) {
      console.error('Erro email:', e);
      return false;
    }
  }

  try {
    if (action === 'register' && request.method === 'POST') {
      const { nome, email, senha } = await request.json();
      if (!nome || !email || !senha) {
        return new Response(JSON.stringify({ ok: false, error: 'Missing fields' }), { headers: corsHeaders });
      }

      const exists = await DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (exists) {
        return new Response(JSON.stringify({ ok: false, error: 'Email já cadastrado' }), { headers: corsHeaders });
      }

      const senha_hash = await hashPassword(senha);
      const code = genCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      await DB.prepare(`
        INSERT INTO users (nome, email, senha_hash, email_code, email_verified, code_expires) 
        VALUES (?, ?, ?, ?, 0, ?)
      `).bind(nome, email, senha_hash, code, expires).run();

      const emailOk = await sendEmail(email, code);
      
      return new Response(JSON.stringify({ 
        ok: true, 
        need_verify: true, 
        email: email,
        email_sent: emailOk 
      }), { headers: corsHeaders });
    }

    if (action === 'verify_email' && request.method === 'POST') {
      const { email, code } = await request.json();
      if (!email || !code) {
        return new Response(JSON.stringify({ ok: false, error: 'Missing fields' }), { headers: corsHeaders });
      }

      const user = await DB.prepare(`
        SELECT id, nome, email, email_code, code_expires 
        FROM users WHERE email = ?
      `).bind(email).first();

      if (!user) {
        return new Response(JSON.stringify({ ok: false, error: 'Usuário não encontrado' }), { headers: corsHeaders });
      }

      if (user.email_code !== code) {
        return new Response(JSON.stringify({ ok: false, error: 'Código inválido' }), { headers: corsHeaders });
      }

      if (new Date(user.code_expires) < new Date()) {
        return new Response(JSON.stringify({ ok: false, error: 'Código expirado' }), { headers: corsHeaders });
      }

      await DB.prepare('UPDATE users SET email_verified = 1, email_code = NULL WHERE id = ?').bind(user.id).run();

      const token = genToken(user.id);
      return new Response(JSON.stringify({ 
        ok: true, 
        token, 
        nome: user.nome, 
        email: user.email 
      }), { headers: corsHeaders });
    }

    if (action === 'resend_code' && request.method === 'POST') {
      const { email } = await request.json();
      const user = await DB.prepare('SELECT id, email_verified FROM users WHERE email = ?').bind(email).first();
      
      if (!user) {
        return new Response(JSON.stringify({ ok: false, error: 'Email não encontrado' }), { headers: corsHeaders });
      }
      
      if (user.email_verified) {
        return new Response(JSON.stringify({ ok: false, error: 'Email já confirmado' }), { headers: corsHeaders });
      }

      const code = genCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      
      await DB.prepare('UPDATE users SET email_code = ?, code_expires = ? WHERE id = ?')
        .bind(code, expires, user.id).run();

      const emailOk = await sendEmail(email, code);
      return new Response(JSON.stringify({ ok: true, email_sent: emailOk }), { headers: corsHeaders });
    }

    if (action === 'login_user' && request.method === 'POST') {
      const { email, senha } = await request.json();
      if (!email || !senha) {
        return new Response(JSON.stringify({ ok: false, error: 'Missing fields' }), { headers: corsHeaders });
      }

      const user = await DB.prepare(`
        SELECT id, nome, email, senha_hash, email_verified 
        FROM users WHERE email = ?
      `).bind(email).first();

      if (!user) {
        return new Response(JSON.stringify({ ok: false, error: 'Email ou senha inválidos' }), { headers: corsHeaders });
      }

      const valid = await verifyPassword(senha, user.senha_hash);
      if (!valid) {
        return new Response(JSON.stringify({ ok: false, error: 'Email ou senha inválidos' }), { headers: corsHeaders });
      }

      if (!user.email_verified) {
        const code = genCode();
        const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await DB.prepare('UPDATE users SET email_code = ?, code_expires = ? WHERE id = ?')
          .bind(code, expires, user.id).run();
        await sendEmail(email, code);
        
        return new Response(JSON.stringify({ 
          ok: false, 
          need_verify: true, 
          email: email 
        }), { headers: corsHeaders });
      }

      const token = genToken(user.id);
      return new Response(JSON.stringify({ 
        ok: true, 
        token, 
        nome: user.nome, 
        email: user.email 
      }), { headers: corsHeaders });
    }

    const userId = token ? verifyToken(token) : null;
    if (!userId && action !== 'data') {
      return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { 
        status: 401, 
        headers: corsHeaders 
      });
    }

    if (action === 'user_bms' && request.method === 'GET') {
      const bms = await DB.prepare(`
        SELECT b.code, ub.bms_nome as nome, b.voltage, b.soc, b.online, b.updated_at
        FROM user_bms ub
        JOIN bms_master bm ON ub.bms_code = bm.code
        LEFT JOIN bms b ON bm.code = b.code
        WHERE ub.user_id = ?
        ORDER BY ub.created_at DESC
      `).bind(userId).all();
      
      return new Response(JSON.stringify(bms.results || []), { headers: corsHeaders });
    }

    if (action === 'add_bms' && request.method === 'POST') {
      const { code, nome } = await request.json();
      if (!code || code.length !== 14) {
        return new Response(JSON.stringify({ ok: false, error: 'Código inválido' }), { headers: corsHeaders });
      }

      await DB.prepare('INSERT OR IGNORE INTO bms_master (code) VALUES (?)').bind(code).run();
      
      try {
        await DB.prepare('INSERT INTO user_bms (user_id, bms_code, bms_nome) VALUES (?, ?, ?)')
          .bind(userId, code, nome || code).run();
        return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: 'BMS já adicionada' }), { headers: corsHeaders });
      }
    }

    if (action === 'remove_bms' && request.method === 'DELETE') {
      const code = url.searchParams.get('code');
      await DB.prepare('DELETE FROM user_bms WHERE user_id = ? AND bms_code = ?')
        .bind(userId, code).run();
      return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
    }

    if (action === 'data' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      const data = await DB.prepare('SELECT * FROM bms WHERE code = ?').bind(code).first();
      if (!data) {
        return new Response(JSON.stringify({ ok: false, error: 'BMS não encontrada' }), { headers: corsHeaders });
      }
      data.cells = data.cells ? JSON.parse(data.cells) : [];
      return new Response(JSON.stringify(data), { headers: corsHeaders });
    }

    return new Response(JSON.stringify({ ok: false, error: 'Invalid action' }), { 
      status: 400, 
      headers: corsHeaders 
    });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e.message }), { 
      status: 500, 
      headers: corsHeaders 
    });
  }
}

async function hashPassword(pass) {
  const msgUint8 = new TextEncoder().encode(pass);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(pass, hash) {
  const newHash = await hashPassword(pass);
  return newHash === hash;
}
