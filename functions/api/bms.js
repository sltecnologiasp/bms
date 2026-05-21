let BMS_DB = [
  {
    code: 'SL77777777',
    nome: 'Bateria Oficina',
    soc: 92.1,
    voltage: 54.1,
    current: 5.2,
    temp: 28.5,
    online: 1,
    cells: [3.38, 3.37, 3.38, 3.36, 3.37, 3.38, 3.36, 3.37, 3.38, 3.36, 3.37, 3.38, 3.36, 3.37, 3.38, 3.36]
  }
];

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  if (action === 'login' && request.method === 'POST') {
    const { code } = await request.json();
    const bms = BMS_DB.find(b => b.code === code);
    if (!bms) return new Response(JSON.stringify({ ok: false, error: 'BMS não encontrada' }), { status: 404, headers });
    return new Response(JSON.stringify({ ok: true, token: btoa(JSON.stringify({ code })) }), { headers });
  }

  if (action === 'dados' && request.method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (!auth) return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const token = auth.replace('Bearer ', '');
    const { code } = JSON.parse(atob(token));
    const bms = BMS_DB.find(b => b.code === code);
    return new Response(JSON.stringify(bms || {}), { headers });
  }

  if (action === 'admin_login' && request.method === 'POST') {
    const { user, password } = await request.json();
    if (user === 'admin' && password === 'admin123') {
      return new Response(JSON.stringify({ ok: true, token: 'admin_ok' }), { headers });
    }
    return new Response(JSON.stringify({ ok: false, error: 'Usuário ou senha inválidos' }), { status: 401, headers });
  }

  if (action === 'listar' && request.method === 'GET') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    return new Response(JSON.stringify(BMS_DB), { headers });
  }

  if (action === 'cadastrar' && request.method === 'POST') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const { code, nome } = await request.json();
    if (BMS_DB.find(b => b.code === code)) {
      return new Response(JSON.stringify({ ok: false, error: 'BMS já existe' }), { status: 400, headers });
    }
    BMS_DB.push({ code, nome, soc: 0, voltage: 0, current: 0, temp: 0, online: 0, cells: [] });
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (action === 'deletar' && request.method === 'DELETE') {
    const auth = request.headers.get('Authorization');
    if (auth !== 'Bearer admin_ok') return new Response(JSON.stringify({ ok: false }), { status: 401, headers });
    const code = url.searchParams.get('code');
    BMS_DB = BMS_DB.filter(b => b.code !== code);
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  return new Response(JSON.stringify({ ok: false, error: 'Ação inválida' }), { status: 400, headers });
}
