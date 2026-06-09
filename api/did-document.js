// Vercel Serverless Function — DID Document per did:web
// GET /.well-known/did.json (rewrite configurato in vercel.json)
// La chiave pubblica è derivata dalla stessa VC_SIGNING_PRIVATE_KEY usata in api/sign.js

const { createPrivateKey, createPublicKey } = require('crypto');

const VC_DID = 'did:web:hubs-transparentia.vercel.app';

function parsePem(raw) {
  let pem = raw
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .trim();
  if (!pem.startsWith('-----')) {
    pem = '-----BEGIN PRIVATE KEY-----\n' + pem + '\n-----END PRIVATE KEY-----';
  }
  const match = pem.match(/(-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----)/);
  if (match) pem = match[1];
  return pem;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');

  const rawPem = process.env.VC_SIGNING_PRIVATE_KEY;
  if (!rawPem) {
    return res.status(503).json({ error: 'VC_SIGNING_PRIVATE_KEY non configurata — DID Document non disponibile' });
  }

  try {
    const pem = parsePem(rawPem);
    const privateKey = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
    const publicKey  = createPublicKey(privateKey);
    const pubJwk     = publicKey.export({ format: 'jwk' });
    // pubJwk: { kty: 'OKP', crv: 'Ed25519', x: '<base64url 32 bytes>' }

    const didDoc = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
      ],
      'id': VC_DID,
      'verificationMethod': [{
        'id':           `${VC_DID}#key-1`,
        'type':         'JsonWebKey2020',
        'controller':   VC_DID,
        'publicKeyJwk': pubJwk
      }],
      'authentication':  [`${VC_DID}#key-1`],
      'assertionMethod': [`${VC_DID}#key-1`]
    };

    return res.status(200).json(didDoc);
  } catch (err) {
    const pemSnippet = rawPem ? rawPem.substring(0, 30).replace(/\n/g, '\\n') + '...' : '(vuoto)';
    return res.status(500).json({
      error: `Errore DID Document: ${err.message}`,
      hint: `Primi 30 char env var: "${pemSnippet}". ` +
            'Assicurarsi che la chiave sia PKCS#8 PEM (-----BEGIN PRIVATE KEY-----).'
    });
  }
};
