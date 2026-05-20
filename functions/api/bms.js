export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const cors = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization','Content-Type':'application/json'};
  if (request.method === 'OPTIONS') return new Response(null, { headers: cors });
  
  try {
    if (action === 'login' && request.method === 'POST') {
      const { code } = await request.json();
      const r = await env.DB.prepare('SELECT code FROM bms WHERE code=?').bind(code).first();
      if (!r) return Response.json({error:'BMS não cadastrada'}, {headers:cors});
      return Response.json({ok:1,token:code}, {headers:cors});
    }
    if (action === 'admin_login' && request.method === 'POST') {
      const { user, password } = await request.json();
      if (user === env.ADMIN_USER && password === env.ADMIN_PASS) return Response.json({ok:1,token:'admin_ok'}, {headers:cors});
      return Response.json({error:'Credenciais inválidas'}, {headers:cors});
    }
    if (action === 'dados' && request.method === 'GET') {
      const auth = request.headers.get('authorization')?.split(' ')[1];
      const r = await env.DB.prepare('SELECT * FROM bms WHERE code=?').bind(auth).first();
      if (!r) return Response.json({error:'Não encontrada'}, {status:401,headers:cors});
      return Response.json({...r,cells:JSON.parse(r.cells||'[]'),online:new Date()-new Date(r.last_update)<30000}, {headers:cors});
    }
    if (action === 'cadastrar' &&
cat >> functions/api/bms.js << 'EOF'
    if (action === 'cadastrar' && request.method === 'POST') {
      const auth = request.headers.get('authorization');
      if (auth!== 'Bearer admin_ok') return Response.json({error:'Não autorizado'}, {status:401,headers:cors});
      const { code, nome } = await request.json();
      if (!code?.startsWith('SL') || code.length!== 10) return Response.json({error:'Código deve ser SL + 8 dígitos'}, {headers:cors});
      await env.DB.prepare('INSERT INTO bms(code,nome) VALUES(?,?)').bind(code,nome||'').run();
      return Response.json({ok:1}, {headers:cors});
    }
    if (action === 'listar' && request.method === 'GET') {
      const auth = request.headers.get('authorization');
      if (auth!== 'Bearer admin_ok') return Response.json({error:'Não autorizado'}, {status:401,headers:cors});
      const { results } = await env.DB.prepare('SELECT * FROM bms ORDER BY created_at DESC').all();
      return Response.json(results.map(r=>({...r,cells:JSON.parse(r.cells||'[]'),online:new Date()-new Date(r.last_update)<30000})), {headers:cors});
    }
    if (action === 'deletar' && request.method === 'DELETE') {
      const auth = request.headers.get('authorization');
      if (auth!== 'Bearer admin_ok') return Response.json({error:'Não autorizado'}, {status:401,headers:cors});
      const code = url.searchParams.get('code');
      await env.DB.prepare('DELETE FROM bms WHERE code=?').bind(code).run();
      return Response.json({ok:1}, {headers:cors});
    }
    if (action === 'update' && request.method === 'POST') {
      const { code, soc, voltage, current, temp, cells } = await request.json();
      await env.DB.prepare('UPDATE bms SET soc=?,voltage=?,current=?,temp=?,cells=?,last_update=CURRENT_TIMESTAMP WHERE code=?').bind(soc,voltage,current,temp,JSON.stringify(cells||[]),code).run();
      return Response.json({ok:1}, {headers:cors});
    }
    return Response.json({error:'Ação não encontrada'}, {status:404,headers:cors});
  } catch(e) {
    return Response.json({error:e.message}, {status:500,headers:cors});
  }
}
