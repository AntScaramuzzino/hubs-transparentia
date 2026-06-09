// Vercel Serverless Function — firma Ed25519 per Verifiable Credentials
// Env var richiesta: VC_SIGNING_PRIVATE_KEY (chiave Ed25519 PKCS#8 PEM)
//
// Generazione chiave (una tantum in locale):
//   node -e "const {generateKeyPairSync}=require('crypto');
//     const kp=generateKeyPairSync('ed25519');
//     console.log(kp.privateKey.export({type:'pkcs8',format:'pem'}));"
// Copiare l'intero output (incluse le righe -----BEGIN/END PRIVATE KEY-----)
// e incollarlo nel campo VC_SIGNING_PRIVATE_KEY su Vercel.

const { createPrivateKey, sign: cryptoSign } = require('crypto');

const ORIGIN_PATTERNS = [
  /^https:\/\/hubs-transparentia[a-z0-9-]*\.vercel\.app$/,
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/
];
const isAllowedOrigin = (o) => ORIGIN_PATTERNS.some((re) => re.test(o));
const VC_DID = 'did:web:hubs-transparentia.vercel.app';

function parsePem(raw) {
  // Normalizza newline (Vercel può avere \n letterale o \\n come escape)
  let pem = raw
    .replace(/\\n/g, '\n')  // escaped \n → newline reale
    .replace(/\r\n/g, '\n') // CRLF → LF
    .trim();

  // Se l'utente ha copiato solo la parte base64 senza header PEM, lo avvolgiamo
  if (!pem.startsWith('-----')) {
    pem = '-----BEGIN PRIVATE KEY-----\n' + pem + '\n-----END PRIVATE KEY-----';
  }

  // Estrai solo il blocco PEM valido (in caso ci sia testo extra prima/dopo)
  const match = pem.match(/(-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----)/);
  if (match) pem = match[1];

  return pem;
}

module.exports = async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (origin && !isAllowedOrigin(origin)) {
    return res.status(403).json({ error: 'Origine non autorizzata' });
  }

  const rawPem = process.env.VC_SIGNING_PRIVATE_KEY;
  if (!rawPem) {
    return res.status(500).json({ error: 'VC_SIGNING_PRIVATE_KEY non configurata su Vercel' });
  }

  const { payload } = req.body || {};
  if (!payload || typeof payload !== 'string') {
    return res.status(400).json({ error: 'Campo payload mancante o non stringa' });
  }
  if (payload.length > 500000) {
    return res.status(400).json({ error: 'Payload troppo grande' });
  }

  try {
    const pem = parsePem(rawPem);
    const privateKey = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });

    if (privateKey.asymmetricKeyType !== 'ed25519') {
      return res.status(500).json({
        error: `Tipo chiave errato: trovato "${privateKey.asymmetricKeyType}", atteso "ed25519". ` +
               'Rigenerare con: node -e "const {generateKeyPairSync}=require(\'crypto\'); ' +
               'const kp=generateKeyPairSync(\'ed25519\'); ' +
               'console.log(kp.privateKey.export({type:\'pkcs8\',format:\'pem\'}))"'
      });
    }

    const data = Buffer.from(payload, 'utf8');
    const signature = cryptoSign(null, data, privateKey);

    return res.status(200).json({
      signature: signature.toString('base64url'),
      algorithm:  'EdDSA',
      keyId:      `${VC_DID}#key-1`
    });
  } catch (err) {
    // Messaggio diagnostico senza esporre la chiave
    const pemSnippet = rawPem ? rawPem.substring(0, 30).replace(/\n/g, '\\n') + '...' : '(vuoto)';
    return res.status(500).json({
      error: `Errore parsing chiave: ${err.message}`,
      hint: `Primi 30 char env var: "${pemSnippet}". ` +
            'Assicurarsi che la chiave sia PKCS#8 PEM (-----BEGIN PRIVATE KEY-----).'
    });
  }
};
