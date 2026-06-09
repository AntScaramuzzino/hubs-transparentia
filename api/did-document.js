// Vercel Serverless Function — DID Document per did:web
// Restituisce il DID Document ufficiale di hubs-transparentia.vercel.app
// raggiungibile via GET /.well-known/did.json (configurato in vercel.json)
//
// La chiave pubblica viene derivata dinamicamente dalla stessa VC_SIGNING_PRIVATE_KEY
// usata in api/sign.js, garantendo che DID document e chiave di firma siano sempre allineati.

const { createPrivateKey, createPublicKey } = require('crypto');

const VC_DID = 'did:web:hubs-transparentia.vercel.app';

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const privateKeyPem = process.env.VC_SIGNING_PRIVATE_KEY;
  if (!privateKeyPem) {
    return res.status(503).json({ error: 'VC_SIGNING_PRIVATE_KEY non configurata — DID Document non disponibile' });
  }

  try {
    const pem = privateKeyPem.replace(/\\n/g, '\n');
    const privateKey = createPrivateKey(pem);
    const publicKey  = createPublicKey(privateKey);
    const pubJwk     = publicKey.export({ format: 'jwk' });
    // pubJwk: { kty: 'OKP', crv: 'Ed25519', x: '<base64url>' }

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
    return res.status(500).json({ error: 'Errore DID Document: ' + err.message });
  }
};
