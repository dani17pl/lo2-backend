// server.js - Lightning Out 2.0 + Salesforce JWT Bearer Flow + Experience Cloud
import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
function normalizeUrl(url) {
  return url ? url.replace(/\/+$/, '') : url;
}

// -----------------------------------------------------------------------------
// CORS
// -----------------------------------------------------------------------------
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://hoteles-lightningout.web.app')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

// -----------------------------------------------------------------------------
// Salesforce PROD / JWT / Experience Cloud
// -----------------------------------------------------------------------------

// Endpoint utilizado para obtener el access_token mediante JWT.
// Actualmente puede mantenerse apuntando al Experience Site porque el JWT ya
// está funcionando correctamente con esta configuración.
const LOGIN_URL = normalizeUrl(process.env.SF_LOGIN_URL || 'https://login.salesforce.com');

// Experience Cloud Site utilizado para crear la sesión aislada del Site.
const SITE_URL = normalizeUrl(process.env.SF_SITE_URL || 'https://pghsa.my.site.com');

const CLIENT_ID = process.env.SF_CLIENT_ID;
const USERNAME = process.env.SF_USERNAME;

// Nueva Lightning Out 2.0 App vinculada al Experience Site.
const LIGHTNING_OUT_APP_ID = process.env.SF_LIGHTNING_OUT_APP_ID || '1UsaT00000000eLSAQ';

// En Render se recomienda SF_PRIVATE_KEY.
// Para desarrollo local también se admite SF_PRIVATE_KEY_PATH.
const PRIVATE_KEY_ENV = process.env.SF_PRIVATE_KEY;
const PRIVATE_KEY_PATH = process.env.SF_PRIVATE_KEY_PATH;

function log(...args) {
  console.log('[LO2-BACKEND]', ...args);
}

function requireConfig() {
  const missing = [];

  if (!LOGIN_URL) missing.push('SF_LOGIN_URL');
  if (!SITE_URL) missing.push('SF_SITE_URL');
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
    // o como una sola línea usando \n.
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

// -----------------------------------------------------------------------------
// JWT Assertion
// -----------------------------------------------------------------------------
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
// OAuth JWT Bearer: obtener access_token Salesforce
// -----------------------------------------------------------------------------
async function getAccessTokenFromJwt() {
  requireConfig();

  const assertion = createJwtAssertion();

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion
  });

  const tokenUrl = `${LOGIN_URL}/services/oauth2/token`;

  log('Solicitando access_token JWT en:', tokenUrl);

  const response = await fetch(tokenUrl, {
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
    user: USERNAME,
    sfdc_site_url: data.sfdc_site_url || data.sfdc_community_url || null,
    sfdc_site_id: data.sfdc_site_id || null
  });

  return {
    access_token: data.access_token,
    instance_url: data.instance_url,
    scope: data.scope
  };
}

// -----------------------------------------------------------------------------
// Middleware CORS
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
    siteUrl: SITE_URL,
    lightningOutAppId: LIGHTNING_OUT_APP_ID
  });
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Frontdoor Lightning Out 2.0 mediante Experience Cloud
// -----------------------------------------------------------------------------
app.get('/api/lo2/frontdoor', async (req, res) => {
  try {
    // -------------------------------------------------------------------------
    // 1. Obtener access_token mediante JWT Bearer
    // -------------------------------------------------------------------------
    const { access_token, scope } = await getAccessTokenFromJwt();

    if (scope && !scope.split(' ').includes('web') && !scope.split(' ').includes('full')) {
      throw new Error(`El access_token no contiene scope web/full. Scope recibido: ${scope}`);
    }

    // -------------------------------------------------------------------------
    // 2. Generar una nueva sesión UI en el Experience Cloud Site
    //
    // IMPORTANTE:
    // Ya NO utilizamos:
    //
    //   instance_url/services/oauth2/lightningoutsingleaccess
    //
    // porque eso crea el frontdoor en el contexto de la org.
    //
    // Utilizamos:
    //
    //   SITE_URL/services/oauth2/singleaccess
    //
    // para crear el frontdoor en el Experience Cloud Site.
    // -------------------------------------------------------------------------
    const bridgeUrl = `${SITE_URL}/services/oauth2/singleaccess`;

    log('UI Bridge Experience Site:', bridgeUrl);

    const body = new URLSearchParams({
      access_token
    });

    const singleResp = await fetch(bridgeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    const responseText = await singleResp.text();
    let singleData;

    try {
      singleData = JSON.parse(responseText);
    } catch {
      singleData = { rawResponse: responseText };
    }

    if (!singleResp.ok) {
      log('❌ Experience Site singleaccess KO:', singleResp.status, singleData);

      return res.status(502).json({
        error: 'experience_site_singleaccess_failed',
        status: singleResp.status,
        detail: singleData
      });
    }

    const frontdoorUrl = singleData.frontdoor_uri || singleData.frontdoorUrl;

    if (!frontdoorUrl) {
      log('❌ Respuesta de Experience Site sin frontdoor_uri:', singleData);

      return res.status(502).json({
        error: 'no_frontdoor_in_response',
        data: singleData
      });
    }

    // -------------------------------------------------------------------------
    // 3. No cachear ni registrar la frontdoor_uri
    // -------------------------------------------------------------------------
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    log('✅ frontdoorUrl de Experience Cloud generado');
    log('✅ Lightning Out App ID:', LIGHTNING_OUT_APP_ID);

    return res.json({
      frontdoorUrl
    });

  } catch (error) {
    log('💥 Error en /api/lo2/frontdoor:', error.message);

    return res.status(500).json({
      error: 'server_error',
      message: error.message
    });
  }
});

// -----------------------------------------------------------------------------
// Start
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  log(`Servidor escuchando en puerto ${PORT}`);
  log(`Salesforce login JWT: ${LOGIN_URL}`);
  log(`Experience Cloud Site: ${SITE_URL}`);
  log(`Usuario JWT: ${USERNAME || '(sin configurar)'}`);
  log(`Lightning Out App ID: ${LIGHTNING_OUT_APP_ID}`);
});