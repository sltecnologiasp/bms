export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  
  // CORS
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  // Lista todas as BMS - por enquanto hardcoded
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
      },
      {
        code: 'SL82576655',
        nome: 'Bateria Teste',
        soc: 45.0,
        voltage: 52.3,
        current: -2.1,
        temp: 31.2,
        online: 0,
        cells: [3.25, 3.26, 3.24, 3.27]
      }
    ];
    return new Response(JSON.stringify({ ok: true, data: bms }), { headers });
  }

  return new Response(JSON.stringify({ ok: false, error: 'Ação inválida' }), { status: 400, headers });
}
