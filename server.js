// server.js - Lightning Out 2.0 + Salesforce JWT Bearer Flow (PROD)
import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
// CORS
// -----------------------------------------------------------------------------
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://hoteles-lightningout.web.app')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

// -----------------------------------------------------------------------------
// Salesforce PROD / JWT
// -----------------------------------------------------------------------------
const LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com';
const CLIENT_ID = process.env.SF_CLIENT_ID;
const USERNAME = process.env.SF_USERNAME;
const LIGHTNING_OUT_APP_ID = process.env.SF_LIGHTNING_OUT_APP_ID || '1UsaT00000000cjSAA';

// En Render se recomienda SF_PRIVATE_KEY.
// Para desarrollo local también se admite SF_PRIVATE_KEY_PATH.
const PRIVATE_KEY_ENV = process.env.SF_PRIVATE_KEY;
const PRIVATE_KEY_PATH = process.env.SF_PRIVATE_KEY_PATH;

function log(...args) {
  console.log('[LO2-BACKEND]', ...args);
}

function requireConfig() {
  const missing = [];

  if (!CLIENT_ID) missing.push('SF_CLIENT_ID');
  if (!USERNAME) missing.push('SF_USERNAME');
  if (!LIGHTNING_OUT_APP_ID) missing.push('SF_LIGHTNING_OUT_APP_ID');
  if (!PRIVATE_KEY_ENV && !PRIVATE_KEY_PATH) {
    missing.push('SF_PRIVATE_KEY o SF_PRIVATE_KEY_PATH');
  }

  if (missing.length) {
    throw new Error(`Faltan variables de entorno: ${missing.join(', ')}`);
  }
}

function getPrivateKey() {
  if (PRIVATE_KEY_ENV) {
    // Permite guardar el secreto en Render con saltos de línea reales
    // o como una sola línea usando \\n.
    return PRIVATE_KEY_ENV.replace(/\\n/g, '\n').trim();
  }

  if (!fs.existsSync(PRIVATE_KEY_PATH)) {
    throw new Error(`No existe SF_PRIVATE_KEY_PATH: ${PRIVATE_KEY_PATH}`);
  }

  return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8').trim();
}

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function createJwtAssertion() {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: 'RS256',
    typ: 'JWT'
  };

  const payload = {
    iss: CLIENT_ID,
    sub: USERNAME,
    aud: LOGIN_URL,
    exp: now + 180
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsignedToken);
  signer.end();

  const signature = signer.sign(getPrivateKey());
  return `${unsignedToken}.${base64url(signature)}`;
}

// -----------------------------------------------------------------------------
// OAuth JWT Bearer: access_token Salesforce
// -----------------------------------------------------------------------------
async function getAccessTokenFromJwt() {
  requireConfig();

  const assertion = createJwtAssertion();

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion
  });

  const response = await fetch(`${LOGIN_URL}/services/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: body.toString()
  });

  const text = await response.text();
  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = { rawResponse: text };
  }

  if (!response.ok) {
    log('❌ JWT Bearer KO:', response.status, data);
    throw new Error(`JWT Bearer KO (${response.status}): ${JSON.stringify(data)}`);
  }

  if (!data.access_token || !data.instance_url) {
    throw new Error('Salesforce no devolvió access_token o instance_url.');
  }

  log('✅ JWT Bearer OK:', {
    instance_url: data.instance_url,
    scope: data.scope,
    user: USERNAME
  });

  return {
    access_token: data.access_token,
    instance_url: data.instance_url
  };
}

// -----------------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------------
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

// -----------------------------------------------------------------------------
// Health check
// -----------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Lightning Out 2.0 backend',
    auth: 'Salesforce JWT Bearer Flow',
    loginUrl: LOGIN_URL,
    lightningOutAppId: LIGHTNING_OUT_APP_ID
  });
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Frontdoor Lightning Out 2.0
// -----------------------------------------------------------------------------
app.get('/api/lo2/frontdoor', async (req, res) => {
  try {
    const { access_token, instance_url } = await getAccessTokenFromJwt();

    const body = new URLSearchParams({
      access_token,
      lightning_out_app_id: LIGHTNING_OUT_APP_ID
    });

    const singleResp = await fetch(
      `${instance_url}/services/oauth2/lightningoutsingleaccess`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      }
    );

    const responseText = await singleResp.text();
    let singleData;

    try {
      singleData = JSON.parse(responseText);
    } catch {
      singleData = { rawResponse: responseText };
    }

    if (!singleResp.ok) {
      log('❌ lightningoutsingleaccess KO:', singleResp.status, singleData);
      return res.status(502).json({
        error: 'lightningoutsingleaccess_failed',
        status: singleResp.status,
        detail: singleData
      });
    }

    const frontdoorUrl = singleData.frontdoor_uri || singleData.frontdoorUrl;

    if (!frontdoorUrl) {
      log('❌ Respuesta sin frontdoor_uri:', singleData);
      return res.status(502).json({
        error: 'no_frontdoor_in_response',
        data: singleData
      });
    }

    // La frontdoor URI equivale a una credencial temporal. No se cachea ni se loguea.
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    log('✅ frontdoorUrl de Lightning Out 2.0 generado');
    return res.json({ frontdoorUrl });
  } catch (error) {
    log('💥 Error en /api/lo2/frontdoor:', error.message);

    return res.status(500).json({
      error: 'server_error',
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  log(`Servidor escuchando en puerto ${PORT}`);
  log(`Salesforce login: ${LOGIN_URL}`);
  log(`Usuario JWT: ${USERNAME || '(sin configurar)'}`);
  log(`Lightning Out App ID: ${LIGHTNING_OUT_APP_ID}`);
});
