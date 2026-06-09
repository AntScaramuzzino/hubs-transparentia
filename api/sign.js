// Vercel Serverless Function — firma Ed25519 per Verifiable Credentials
// Richiede env var: VC_SIGNING_PRIVATE_KEY (chiave Ed25519 in formato PEM PKCS#8)
//
// Per generare la chiave (una tantum, da eseguire in locale):
//   node -e "const {generateKeyPairSync}=require('crypto');
//     const kp=generateKeyPairSync('ed25519');
//     console.log(kp.privateKey.export({type:'pkcs8',format:'pem'}));"
// Poi impostare VC_SIGNING_PRIVATE_KEY in Vercel → Settings → Environment Variables
// (sostituire i newline con \n nella stringa)

const { createPrivateKey, sign: cryptoSign } = require('crypto');

const ORIGIN_PATTERNS = [
  /^https:\/\/hubs-transparentia[a-z0-9-]*\.vercel\.app$/,
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/
];
const isAllowedOrigin = (o) => ORIGIN_PATTERNS.some((re) => re.test(o));

const VC_DID = 'did:web:hubs-transparentia.vercel.app';

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

  const privateKeyPem = process.env.VC_SIGNING_PRIVATE_KEY;
  if (!privateKeyPem) {
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
    // Normalizza newline (Vercel env vars usano \n letterale)
    const pem = privateKeyPem.replace(/\\n/g, '\n');
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
      throw new Error('La chiave configurata non è Ed25519');
    }
    const data = Buffer.from(payload, 'utf8');
    const signature = cryptoSign(null, data, privateKey);

    return res.status(200).json({
      signature: signature.toString('base64url'),
      algorithm:  'EdDSA',
      keyId:      `${VC_DID}#key-1`
    });
  } catch (err) {
    return res.status(500).json({ error: 'Errore firma: ' + err.message });
  }
};
