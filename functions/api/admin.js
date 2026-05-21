export async function onRequest(context) {
  const url = new URL(context.request.url);
  const action = url.searchParams.get('action');
  
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  if (action === 'list') {
    const bms = [
      {
        code: 'SL77777777',
        nome: 'Bateria Oficina',
        soc: 92.1,
        voltage: 54.1,
        current: 5.2,
        temp: 28.5,
        online: 1,
        cells: [3.38, 3.37, 3.38, 3.36]
      }
    ];
    return new Response(JSON.stringify({ ok: true, data: bms }), { headers });
  }

  return new Response(JSON.stringify({ ok: false }), { status: 400, headers });
}
