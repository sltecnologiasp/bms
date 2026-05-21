export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  const url = new URL(request.url);
  const action = url.searchParams.get('action') || '';
  
  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { 
      'Content-Type': 'application/json', 
      'Access-Control-Allow-Origin': '*' 
    }
  });

  try {
    // UPDATE - pro simulador ESP32
    if (action.toLowerCase() === 'update' && request.method === 'POST') {
      const data = await request.json();
      const { code, soc, voltage, current, temp, online, cells } = data;
      
      await db.prepare(`
        UPDATE bms SET 
          soc = ?, voltage = ?, current = ?, temp = ?, 
          online = ?, cells = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE code = ?
      `).bind(soc, voltage, current, temp, online, JSON.stringify(cells), code).run();
      
      return json({ ok: true, updated: code });
    }

    // LIST - pro painel admin
    if (action === 'list') {
      const { results } = await db.prepare(`
        SELECT code, client, soc, voltage, current, temp, online, cells, updated_at 
        FROM bms 
        ORDER BY updated_at DESC
      `).all();
      
      const baterias = results.map(b => ({
        ...b,
        cells: b.cells ? JSON.parse(b.cells) : []
      }));
      
      return json({ ok: true, baterias });
    }

    return json({ ok: false, error: 'Ação inválida' }, 400);
    
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
