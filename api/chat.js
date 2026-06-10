// Vercel Serverless Function — proxy Anthropic API
// ANTHROPIC_API_KEY deve essere configurata in Vercel → Settings → Environment Variables

// Origini autorizzate a chiamare l'endpoint (anti-abuso: niente wildcard)
// Copre produzione e deploy di preview del progetto Vercel + sviluppo locale
const ORIGIN_PATTERNS = [
  /^https:\/\/hubs-transparentia[a-z0-9-]*\.vercel\.app$/,
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/
];
const isAllowedOrigin = (o) => ORIGIN_PATTERNS.some((re) => re.test(o));

// Modelli utilizzabili dal client (il default resta haiku; sonnet serve ad analisi_progetto.html)
const ALLOWED_MODELS = [
  'claude-haiku-4-5-20251001',
  'claude-sonnet-4-6'
];

const MAX_TOKENS_CAP = 16000;  // tetto assoluto lato server (analisi progetto: JSON lunghi)
const MAX_MESSAGES = 60;       // limite messaggi per richiesta
const MAX_BODY_CHARS = 200000; // limite dimensione payload messaggi

module.exports = async function handler(req, res) {
  // CORS: riflette l'origin solo se in allowlist
  const origin = req.headers.origin || '';
  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Richieste cross-origin da origini non autorizzate: rifiutate.
  if (origin && !isAllowedOrigin(origin)) {
    return res.status(403).json({ error: 'Origine non autorizzata' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY non configurata su Vercel' });
  }

  const { messages, system, model, max_tokens } = req.body || {};
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Campo messages mancante o non valido' });
  }
  if (messages.length > MAX_MESSAGES) {
    return res.status(400).json({ error: 'Troppi messaggi nella richiesta' });
  }
  if (JSON.stringify(messages).length > MAX_BODY_CHARS) {
    return res.status(400).json({ error: 'Payload troppo grande' });
  }

  // Modello: solo dalla allowlist; tutto il resto ricade sul default
  const safeModel = ALLOWED_MODELS.includes(model) ? model : 'claude-haiku-4-5-20251001';
  // max_tokens: numerico, con tetto server-side
  const safeMaxTokens = Math.min(
    Number.isFinite(Number(max_tokens)) && Number(max_tokens) > 0 ? Number(max_tokens) : 1500,
    MAX_TOKENS_CAP
  );

  try {
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: safeModel,
        max_tokens: safeMaxTokens,
        system: system || '',
        messages
      })
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      return res.status(upstream.status).json({ error: data?.error?.message || 'Errore Anthropic API' });
    }

    return res.status(200).json(data);
  } catch (err) {
    return res.status(502).json({ error: 'Errore di rete verso Anthropic: ' + err.message });
  }
};
