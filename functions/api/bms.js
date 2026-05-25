export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  // LOGIN ADMIN
  if (action === 'admin_login' && request.method === 'POST') {
    const { user, password } = await request.json();
    if (user === 'administrador' && password === '426240637') {
      return new Response(JSON.stringify({ok: true, token: 'admin_ok'}), { headers });
    }
    return new Response(JSON.stringify({error: 'Usuário ou senha incorretos'}), { status: 401, headers });
  }

  // CADASTRAR BMS
  if (action === 'cadastrar' && request.method === 'POST') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response('Nao autorizado', { status: 401, headers });
    const { code, nome } = await request.json();
    await env.DB.prepare('INSERT INTO baterias (code, nome, soc, voltage, current, temp, online) VALUES (?, ?, 0, 0, 0, 0, 0)').bind(code, nome).run();
    return new Response(JSON.stringify({ok: true}), { headers });
  }

  // LISTAR BMS
  if (action === 'listar' && request.method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response('Nao autorizado', { status: 401, headers });
    const { results } = await env.DB.prepare('SELECT * FROM baterias ORDER BY code').all();
    const baterias = results.map(b => ({
      ...b,
      cells: b.cells ? JSON.parse(b.cells) : []
    }));
    return new Response(JSON.stringify(baterias), { headers });
  }

  // DELETAR BMS
  if (action === 'deletar' && request.method === 'DELETE') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response('Nao autorizado', { status: 401, headers });
    const code = url.searchParams.get('code');
    await env.DB.prepare('DELETE FROM baterias WHERE code = ?').bind(code).run();
    return new Response(JSON.stringify({ok: true}), { headers });
  }

  // NOVO: UPDATE_DATA - ESP32 USA ESSA ROTA
  if (action === 'update_data' && request.method === 'POST') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer bms_admin_token_426240637') {
      return new Response('Nao autorizado', { status: 401, headers });
    }
    const data = await request.json();
    const { code, soc, voltage, current, temp, cells, potencia_inversor, tensao_rede, frequencia } = data;
    
    await env.DB.prepare(`
      UPDATE baterias 
      SET soc = ?, voltage = ?, current = ?, temp = ?, cells = ?, 
          potencia_inversor = ?, tensao_rede = ?, frequencia = ?,
          online = 1, ultima_atualizacao = CURRENT_TIMESTAMP 
      WHERE code = ?
    `).bind(
      soc || 0, voltage || 0, current || 0, temp || 0, JSON.stringify(cells || []),
      potencia_inversor || 0, tensao_rede || 0, frequencia || 0,
      code
    ).run();
    
    return new Response(JSON.stringify({ok: true}), { headers });
  }

  return new Response('Not found', { status: 404, headers });
}
