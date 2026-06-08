export async function onRequest({ request }) {
  const url = new URL(request.url);

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: cors });
  }

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' }
  });

  function isCodigoDemo(code) {
    return /^SLDE[0-9A-F]{10}$/.test(String(code || '').trim().toUpperCase());
  }

  function seedFromCode(code) {
    const clean = String(code || '').trim().toUpperCase();
    const hex = clean.replace(/^SLDE/, '') || '1';
    return parseInt(hex, 16) || 1;
  }

  function calcularDemoInteligente(seed) {
    const uid = Number(seed || 1);
    const t = Math.floor(Date.now() / 1000);
    const fase = (t / 60) + (uid % 37);

    function onda(amplitude, velocidade, deslocamento = 0) {
      return Math.sin((fase / velocidade) + deslocamento) * amplitude;
    }

    function limitar(valor, min, max) {
      return Math.max(min, Math.min(max, valor));
    }

    function arredondar(valor, casas = 1) {
      const p = Math.pow(10, casas);
      return Math.round(valor * p) / p;
    }

    const soc = arredondar(limitar(82 + onda(5, 3.5), 76, 88), 0);
    const voltage = arredondar(51.6 + (soc / 100) * 2.1 + onda(0.18, 2.4, 1.2), 2);
    const current = arredondar(onda(14, 1.8, 0.5), 1);
    const temp = arredondar(27.5 + onda(2.2, 4.5, 2.1), 1);

    const invPotenciaBase = Math.abs(onda(1600, 2.1, 0.8));
    const inv_potencia = Math.round(limitar(invPotenciaBase + 450, 180, 3200));
    const inv_tensao_ac = arredondar(220 + onda(2.5, 2.8, 0.4), 1);
    const inv_frequencia = arredondar(60 + onda(0.08, 3.2, 1.8), 2);
    const inv_geracao_dia = arredondar(limitar(4.5 + Math.abs(onda(5.2, 7.0, 0.2)), 0.8, 13.5), 1);

    const cells = [];
    const mediaCelula = voltage / 16;

    for (let i = 0; i < 16; i++) {
      const variacao = Math.sin((fase / 2.7) + i * 0.73) * 0.012;
      cells.push(arredondar(limitar(mediaCelula + variacao, 3.18, 3.38), 2));
    }

    return {
      soc,
      voltage,
      current,
      temp,
      cells,
      online: true,
      inversor_conectado: true,
      bateria_conectada: true,
      inv_potencia,
      inv_tensao_ac,
      inv_frequencia,
      inv_geracao_dia,
      fw: 'DEMO',
      esp_model: 'SMART BMS DEMO'
    };
  }

  const code = String(url.searchParams.get('code') || '').trim().toUpperCase();

  if (!isCodigoDemo(code)) {
    return json({ ok: false, error: 'Código demo inválido' }, 400);
  }

  const demo = calcularDemoInteligente(seedFromCode(code));

  return json({
    ok: true,
    code,
    nome: 'Dispositivo Demonstração',
    updated_at: new Date().toISOString(),
    ...demo
  });
}
