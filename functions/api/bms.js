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
    headers: {...cors, 'Content-Type': 'application/json' }
  });

  try {
    // ==========================================
    // ROTAS PÚBLICAS (NÃO EXIGEM TOKEN / LOGIN)
    // ==========================================

    // ROTA 1: VERIFICAÇÃO DE E-MAIL
    if (action === 'verify_email' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return new Response('Token inválido', { status: 400 });
      const user = await env.DB.prepare('SELECT id FROM users WHERE token_verificacao = ?').bind(token).first();
      if (!user) {
        return new Response(`
          <html lang="pt-BR">
          <body style="background:#05070d;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;margin:0;">
            <div>
              <h1 style="color:#ff4444;font-size:24px;">Link inválido ou expirado</h1>
              <p style="opacity:0.7;">Este link de verificação já foi utilizado ou não existe.</p>
              <a href="/" style="display:inline-block;margin-top:20px;color:#00ffff;text-decoration:none;border:1px solid #00ffff;padding:10px 20px;border-radius:8px;">Voltar ao Início</a>
            </div>
          </body>
          </html>
        `, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      await env.DB.prepare('UPDATE users SET email_verificado = 1, token_verificacao = NULL WHERE id = ?').bind(user.id).run();
      return new Response(`
        <html lang="pt-BR">
        <body style="background:#05070d;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;margin:0;">
          <div>
            <h1 style="color:#00ff88;font-size:28px;margin-bottom:8px;">Conta Ativada!</h1>
            <p style="opacity:0.8;margin-bottom:24px;">Seu e-mail foi verificado com sucesso.</p>
            <a href="/" style="display:inline-block;background:linear-gradient(90deg, #0080ff, #00ffff);color:#fff;text-decoration:none;padding:14px 28px;border-radius:12px;font-weight:bold;box-shadow:0 4px 20px rgba(0,255,255,0.3);">ACESSAR MEU PAINEL</a>
          </div>
        </body>
        </html>
      `, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // ROTA 2: CADASTRO COM DISPARO DO RESEND
    if ((action === 'register' || action === 'register_user') && request.method === 'POST') {
      const { nome, email, resignation, senha } = await request.json();
      const userEmail = (email || resignation || '').trim().toLowerCase();
      if (!nome || !userEmail || !senha) return json({ ok: false, error: 'Dados inválidos' }, 400);
      const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(userEmail).first();
      if (exists) return json({ ok: false, error: 'E-mail já cadastrado' }, 400);
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
      const senha_hash = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      const token_verificacao = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO users (nome, email, senha_hash, email_verificado, token_verificacao) VALUES (?, ?, ?, 0, ?)')
        .bind(nome, userEmail, senha_hash, token_verificacao).run();

      if (env.RESEND_API_KEY) {
        const verifyLink = `${url.origin}${url.pathname}?action=verify_email&token=${token_verificacao}`;
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'SMART BMS <nao-responda@bms.app.br>',
            to: userEmail,
            subject: 'Confirme seu e-mail - SMART BMS',
            html: `
              <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 24px; background: #05070d; color: #ffffff; border-radius: 12px; border: 1px solid rgba(0,255,255,0.1);">
                <h2 style="color: #00ffff; text-align: center; margin-top: 0;">SMART BMS</h2>
                <h3 style="text-align: center; color: #fff;">Bem-vindo(a), ${nome}!</h3>
                <p style="text-align: center; color: #a1aab8; line-height: 1.6;">Confirme seu e-mail para liberar o acesso.</p>
                <div style="text-align: center; margin: 36px 0;"><a href="${verifyLink}" style="background: linear-gradient(90deg, #0080ff, #00ffff); color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 12px; font-weight: bold; font-size: 16px;">ATIVAR MINHA CONTA</a></div>
              </div>
            `
          })
        }).catch(err => console.log('Erro ao enviar e-mail:', err));
      }
      return json({ ok: true });
    }

    // ROTA 3: DISPARAR E-MAIL DE RECUPERAÇÃO AUTÔNOMO
    if (action === 'recover_user' && request.method === 'POST') {
      const { email } = await request.json();
      const cleanEmail = (email || '').trim().toLowerCase();
      if (!cleanEmail) return json({ ok: false, error: 'E-mail obrigatório' }, 400);

      const user = await env.DB.prepare('SELECT id, nome FROM users WHERE email = ?').bind(cleanEmail).first();
      if (!user) return json({ ok: true }); 

      const token_reset = crypto.randomUUID();
      await env.DB.prepare('UPDATE users SET token_verificacao = ? WHERE id = ?').bind(token_reset, user.id).run();

      if (env.RESEND_API_KEY) {
        const resetLink = `${url.origin}/?reset_token=${token_reset}`;
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: 'SMART BMS <nao-responda@bms.app.br>',
            to: cleanEmail,
            subject: 'Redefinição de Senha - SMART BMS',
            html: `
              <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 24px; background: #05070d; color: #ffffff; border-radius: 12px; border: 1px solid rgba(0,255,255,0.1);">
                <h2 style="color: #00ffff; text-align: center; margin-top: 0;">SMART BMS</h2>
                <h3 style="text-align: center; color: #fff;">Olá, ${user.nome}!</h3>
                <p style="text-align: center; color: #a1aab8; line-height: 1.6;">Você solicitou a redefinição de sua senha. Clique no botão abaixo para criar uma nova senha agora mesmo:</p>
                <div style="text-align: center; margin: 36px 0;">
                  <a href="${resetLink}" style="background: linear-gradient(90deg, #0080ff, #00ffff); color: #ffffff; padding: 16px 32px; text-decoration: none; border-radius: 12px; font-weight: bold; font-size: 16px;">REDEFINIR MINHA SENHA</a>
                </div>
                <p style="text-align: center; color: #6b7c96; font-size: 12px;">Se você não solicitou essa mudança, pode ignorar este e-mail.</p>
              </div>
            `
          })
        }).catch(err => console.log('Erro e-mail recuperação:', err));
      }
      return json({ ok: true });
    }

    // ROTA 4: SALVAR NOVA SENHA REDEFINIDA SOZINHO
    if (action === 'reset_password' && request.method === 'POST') {
      const { token, novaSenha } = await request.json();
      if (!token || !novaSenha) return json({ ok: false, error: 'Dados incompletos' }, 400);

      const user = await env.DB.prepare('SELECT id FROM users WHERE token_verificacao = ?').bind(token).first();
      if (!user) return json({ ok: false, error: 'Link de redefinição inválido ou já utilizado.' }, 400);

      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(novaSenha));
      const nova_senha_hash = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');

      await env.DB.prepare('UPDATE users SET senha_hash = ?, token_verificacao = NULL, email_verificado = 1 WHERE id = ?').bind(nova_senha_hash, user.id).run();
      return json({ ok: true });
    }

    // ROTA 5: LOGIN USER
    if (action === 'login' && request.method === 'POST') {
      const { email, senha } = await request.json();
      const cleanEmail = (email || '').trim().toLowerCase();
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senha));
      const senha_hash = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      const user = await env.DB.prepare('SELECT id, nome, email, email_verificado FROM users WHERE email = ? AND senha_hash = ?').bind(cleanEmail, senha_hash).first();
      if (!user) return json({ ok: false, error: 'E-mail ou senha incorretos' }, 401);
      if (user.email_verificado === 0) return json({ ok: false, error: 'Confirme seu e-mail na caixa de entrada antes de acessar.' }, 403);
      const token = btoa(`user:${user.id}:${Date.now()}`);
      return json({ ok: true, token, user: { id: user.id, nome: user.nome, email: user.email } });
    }

    // ROTA 6: LOGIN ADMIN
    if (action === 'login_admin' && request.method === 'POST') {
      const { user, password } = await request.json();
      if (user === 'administrador' && password === '426240637') return json({ ok: true, token: 'admin_ok' });
      return json({ ok: false, error: 'Credenciais inválidas' }, 401);
    }

    // ROTA 7: UPDATE TELEMETRIA DA EQUIPE/BMS
    if (action === 'update' && request.method === 'POST') {
      const { code, soc, voltage, current, temp, cells } = await request.json();
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      await env.DB.prepare(`
        INSERT INTO bms (code, soc, voltage, current, temp, cells, online, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'))
        ON CONFLICT(code) DO UPDATE SET
          soc = excluded.soc, voltage = excluded.voltage, current = excluded.current,
          temp = excluded.temp, cells = excluded.cells, online = 1, updated_at = datetime('now')
      `).bind(code, soc || 0, voltage || 0, current || 0, temp || 0, JSON.stringify(cells || [])).run();
      return json({ ok: true });
    }

    // ==========================================
    // BARREIRA DE SEGURANÇA (TOKEN)
    // ==========================================
    const auth = request.headers.get('Authorization');
    if (!auth?.startsWith('Bearer ')) return json({ ok: false, error: 'Não autorizado' }, 401);
    const token = auth.slice(7);

    let userId = null;
    let isAdmin = false;

    if (token === 'admin_ok') {
      isAdmin = true;
    } else {
      try {
        const decoded = atob(token);
        const parts = decoded.split(':');
        if (parts[0] === 'user') userId = parseInt(parts[1]);
        else return json({ ok: false, error: 'Token inválido' }, 401);
      } catch {
        return json({ ok: false, error: 'Token inválido' }, 401);
      }
    }

    // VERIFICAÇÃO ADICIONAL DE SEGURANÇA PARA USUÁRIOS
    if (!isAdmin && userId) {
      const userCheck = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
      if (!userCheck) {
        return json({ ok: false, error: 'Sessão inválida ou usuário removido' }, 401);
      }
    }

    // ==========================================
    // ROTAS PROTEGIDAS - EXCLUSIVAS DO ADMIN
    // ==========================================
    if (isAdmin) {
      // LISTAR TODAS AS BMS PARA O ADMIN (CORRIGIDO COM STATUS ONLINE EM TEMPO REAL)
      if (action === 'admin_list_master' && request.method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT bm.code, bm.user_id, b.soc, b.voltage, b.current, b.temp, b.cells, 
                 datetime(b.updated_at) || 'Z' as updated_at,
                 u.nome as dono_nome, u.email as dono_email
          FROM bms_master bm
          LEFT JOIN bms b ON b.code = bm.code
          LEFT JOIN users u ON u.id = bm.user_id
        `).all();
        
        const now = Date.now();
        const data = (results || []).map(item => ({
          ...item,
          cells: JSON.parse(item.cells || '[]'),
          online: item.updated_at && (now - new Date(item.updated_at).getTime() < 5000)
        }));
        return json(data);
      }

      // CADASTRAR NOVA BMS MASTER NO SISTEMA
      if (action === 'admin_add_master' && request.method === 'POST') {
        const { code } = await request.json();
        if (!code) return json({ ok: false, error: 'Código inválido' }, 400);
        try {
          await env.DB.prepare('INSERT INTO bms_master (code, user_id) VALUES (?, NULL)').bind(code).run();
          return json({ ok: true });
        } catch (err) {
          return json({ ok: false, error: 'Este código de BMS já existe no sistema' }, 400);
        }
      }

      // DELETAR BMS MASTER
      if (action === 'deletar' && request.method === 'DELETE') {
        const code = url.searchParams.get('code');
        if (!code) return json({ ok: false, error: 'Código inválido' }, 400);
        await env.DB.prepare('DELETE FROM bms_master WHERE code = ?').bind(code).run();
        await env.DB.prepare('DELETE FROM user_bms WHERE bms_code = ?').bind(code).run();
        await env.DB.prepare('DELETE FROM bms WHERE code = ?').bind(code).run();
        return json({ ok: true });
      }

      // LISTAR TODOS OS CLIENTES
      if (action === 'all_users' && request.method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT u.id, u.nome, u.email, u.created_at, COUNT(bm.id) as bms_count
          FROM users u
          LEFT JOIN bms_master bm ON bm.user_id = u.id
          GROUP BY u.id
          ORDER BY u.id DESC
        `).all();
        return json(results || []);
      }

      // EDITAR CLIENTE
      if (action === 'edit_user' && request.method === 'POST') {
        const { id, nome, email } = await request.json();
        await env.DB.prepare('UPDATE users SET nome = ?, email = ? WHERE id = ?').bind(nome, email.trim().toLowerCase(), id).run();
        return json({ ok: true });
      }

      // EXCLUIR CLIENTE
      if (action === 'delete_user' && request.method === 'DELETE') {
        const id = url.searchParams.get('id');
        if (!id) return json({ ok: false, error: 'ID inválido' }, 400);
        await env.DB.prepare('UPDATE bms_master SET user_id = NULL WHERE user_id = ?').bind(id).run();
        await env.DB.prepare('DELETE FROM user_bms WHERE user_id = ?').bind(id).run();
        await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
        return json({ ok: true });
      }
    }

    // ==========================================
    // ROTAS PROTEGIDAS - EXCLUSIVAS DO USUÁRIO
    // ==========================================
    if (action === 'add_bms' && request.method === 'POST') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const { code, nome } = await request.json();
      if (!code?.startsWith('SL') || code.length !== 14) return json({ ok: false, error: 'Código inválido. Use SL + 12 números' }, 400);
      const bms = await env.DB.prepare("SELECT id, user_id FROM bms_master WHERE code = ?").bind(code).first();
      if (!bms) return json({ ok: false, error: 'BMS não encontrada no sistema' });
      if (bms.user_id && bms.user_id !== userId) return json({ ok: false, error: 'Essa BMS já está vinculada a outra conta' });
      if (bms.user_id === userId) return json({ ok: false, error: 'Você já adicionou essa BMS' });
      await env.DB.prepare("UPDATE bms_master SET user_id = ? WHERE id = ?").bind(userId, bms.id).run();
      await env.DB.prepare('INSERT OR IGNORE INTO bms (code, nome) VALUES (?, ?)').bind(code, nome || code).run();
      await env.DB.prepare('INSERT INTO user_bms (user_id, bms_code, bms_nome) VALUES (?, ?, ?)').bind(userId, code, nome || code).run();
      return json({ ok: true });
    }

    if (action === 'remove_bms' && request.method === 'DELETE') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const code = url.searchParams.get('code');
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      const check = await env.DB.prepare('SELECT id FROM bms_master WHERE code = ? AND user_id = ?').bind(code, userId).first();
      if (!check) return json({ ok: false, error: 'BMS não encontrada na sua conta' }, 403);
      await env.DB.prepare('UPDATE bms_master SET user_id = NULL WHERE code = ?').bind(code).run();
      await env.DB.prepare('DELETE FROM user_bms WHERE user_id = ? AND bms_code = ?').bind(userId, code).run();
      return json({ ok: true });
    }

    if (action === 'user_bms' && request.method === 'GET') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const { results } = await env.DB.prepare(`
        SELECT m.code, ub.bms_nome as nome, datetime(b.updated_at) || 'Z' as updated_at, b.soc, b.voltage
        FROM bms_master m
        LEFT JOIN user_bms ub ON ub.bms_code = m.code AND ub.user_id = m.user_id
        LEFT JOIN bms b ON b.code = m.code
        WHERE m.user_id = ? ORDER BY m.id DESC
      `).bind(userId).all();
      const now = Date.now();
      const withOnline = (results || []).map(r => ({
        ...r,
        online: r.updated_at && (now - new Date(r.updated_at).getTime() < 5000)
      }));
      return json(withOnline);
    }

    // ROTA COMPARTILHADA (DATA DETALHADA) - SUPORTA USER E ADMIN
    if (action === 'data' && request.method === 'GET') {
      const code = url.searchParams.get('code');
      if (!code) return json({ ok: false, error: 'Code obrigatório' }, 400);
      if (userId && !isAdmin) {
        const check = await env.DB.prepare('SELECT id FROM user_bms WHERE user_id = ? AND bms_code = ?').bind(userId, code).first();
        if (!check) return json({ ok: false, error: 'Acesso negado' }, 403);
      }
      const data = await env.DB.prepare('SELECT *, datetime(updated_at) || "Z" as updated_at FROM bms WHERE code = ?').bind(code).first();
      if (!data) return json({ ok: false, error: 'BMS não encontrada' }, 404);
      const online = data.updated_at && (Date.now() - new Date(data.updated_at).getTime() < 5000);
      return json({...data, online, cells: JSON.parse(data.cells || '[]')});
    }

    // ALTERAR SENHA POR DENTRO DO PAINEL DE CLIENTES
    if (action === 'user_change_password' && request.method === 'POST') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      const { senhaAtual, novaSenha } = await request.json();
      
      const hashAtual = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(senhaAtual));
      const senha_atual_hash = Array.from(new Uint8Array(hashAtual)).map(b => b.toString(16).padStart(2, '0')).join('');
      
      const user = await env.DB.prepare('SELECT id FROM users WHERE id = ? AND senha_hash = ?').bind(userId, senha_atual_hash).first();
      if (!user) return json({ ok: false, error: 'Senha atual incorreta' }, 400);
      
      const hashNova = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(novaSenha));
      const nova_senha_hash = Array.from(new Uint8Array(hashNova)).map(b => b.toString(16).padStart(2, '0')).join('');
      
      await env.DB.prepare('UPDATE users SET senha_hash = ? WHERE id = ?').bind(nova_senha_hash, userId).run();
      return json({ ok: true });
    }

    // EXCLUIR A PRÓPRIA CONTA LOGADA PELO PAINEL
    if (action === 'user_delete_self' && request.method === 'DELETE') {
      if (!userId) return json({ ok: false, error: 'Login necessário' }, 401);
      
      await env.DB.prepare('UPDATE bms_master SET user_id = NULL WHERE user_id = ?').bind(userId).run();
      await env.DB.prepare('DELETE FROM user_bms WHERE user_id = ?').bind(userId).run();
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
      
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}