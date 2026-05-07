// server.js
import express from 'express';
import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
// ------------- CORS ---------------------
const allowedOrigins = [
  'https://hoteles-lightningout.web.app'
];

// ------------- Config Salesforce -----------------
const LOGIN_URL     = process.env.SF_LOGIN_URL;      // My Domain o sandbox (https://pghsa--devomega.sandbox.my.salesforce.com)
const CLIENT_ID     = process.env.SF_CLIENT_ID;
const CLIENT_SECRET = process.env.SF_CLIENT_SECRET;
// Debe ser EXACTAMENTE igual a una Callback URL de la Connected App
// Ejemplo: http://localhost:3000/api/lo2/callback
const CALLBACK_URL  = process.env.SF_CALLBACK_URL;

// En memoria para la demo (luego lo puedes guardar en BBDD, Secret Manager, etc.)
let REFRESH_TOKEN = process.env.SF_REFRESH_TOKEN || null;

// ------------- Helper: log sencillo ----------------
function log(...args) {
  console.log('[LO2-BACKEND]', ...args);
}

// ------------- CORS muy básico ---------------------
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

// ------------- Home de prueba ----------------------
app.get('/', (req, res) => {
  res.send('Backend LO2 OK. Visita /auth/login una vez para obtener SF_REFRESH_TOKEN.');
});

// ------------- 1) Iniciar login (OAuth Web Server Flow) ---
app.get('/auth/login', (req, res) => {
  // scope: api + web + refresh_token
  const scope = encodeURIComponent('api web refresh_token');

  const authUrl =
    `${LOGIN_URL}/services/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(CALLBACK_URL)}` +
    `&scope=${scope}`;

  log('Redirigiendo a Salesforce para login:', authUrl);
  res.redirect(authUrl);
});

// ------------- 2) Callback OAuth --------------------
// IMPORTANTE: esta ruta debe coincidir con SF_CALLBACK_URL
// Ejemplo: SF_CALLBACK_URL=http://localhost:3000/api/lo2/callback
app.get('/api/lo2/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    log('❌ Error en callback OAuth:', error, error_description);
    return res.status(400).send(`Error en OAuth: ${error} - ${error_description}`);
  }

  if (!code) {
    return res.status(400).send('Falta parámetro ?code en el callback.');
  }

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: CALLBACK_URL
    });

    const tokenResp = await fetch(`${LOGIN_URL}/services/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });

    const data = await tokenResp.json();

    if (!tokenResp.ok) {
      log('❌ Error al canjear code por token:', tokenResp.status, data);
      return res
        .status(500)
        .send(`Error al canjear code por token: ${tokenResp.status} - ${JSON.stringify(data)}`);
    }

    log('✅ Login Salesforce OK, usuario (id URL):', data.id);
    log('   instance_url  :', data.instance_url);
    log('   scopes        :', data.scope);
    log('   refresh_token :', data.refresh_token ? '(recibido)' : '(NO recibido)');

    if (!data.refresh_token) {
      return res.status(500).send(
        'No se ha recibido refresh_token. ' +
        'Asegúrate de que la Connected App tiene el scope "refresh_token" u "offline_access" ' +
        'y de que no habías autorizado antes esta app (revoca el permiso y vuelve a intentar).'
      );
    }

    // Guardamos el refresh token en memoria
    REFRESH_TOKEN = data.refresh_token;

    // En la práctica, aquí deberías persistirlo en BBDD o secreto seguro.
    log('⭐ Copia este SF_REFRESH_TOKEN y guárdalo en tu .env:');
    console.log('\nSF_REFRESH_TOKEN=', data.refresh_token, '\n');

    res.send(
      'OAuth completado. Mira la consola del backend para copiar SF_REFRESH_TOKEN ' +
      'y pegarlo en tu .env. Luego reinicia el servidor y ya podrás usar /api/lo2/frontdoor.'
    );
  } catch (e) {
    log('💥 Error en /api/lo2/callback:', e);
    res.status(500).send('Error interno en /api/lo2/callback');
  }
});

// ------------- Helper: renovar access_token ---------
async function getAccessTokenFromRefresh() {
  if (!REFRESH_TOKEN) {
    throw new Error(
      'No hay REFRESH_TOKEN. Ejecuta /auth/login una vez y completa el flujo OAuth.'
    );
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: REFRESH_TOKEN
  });

  const resp = await fetch(`${LOGIN_URL}/services/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  const data = await resp.json();

  if (!resp.ok) {
    log('❌ Error al renovar access_token con refresh_token:', resp.status, data);
    throw new Error(`Refresh token KO: ${resp.status} - ${JSON.stringify(data)}`);
  }

  log('✅ Access token renovado. scopes:', data.scope);

  return {
    access_token: data.access_token,
    instance_url: data.instance_url
  };
}

// ------------- 3) Endpoint para LO2: frontdoor -------
// Puedes pasar ?redirect_uri=lightning/page/home, lightning/setup/..., etc.
app.get('/api/lo2/frontdoor', async (req, res) => {
  try {
    const { access_token, instance_url } = await getAccessTokenFromRefresh();

    const redirectUri = req.query.redirect_uri;

    const body = new URLSearchParams();

    if (redirectUri) {
      body.set('redirect_uri', redirectUri);
    }

    const singleResp = await fetch(
      `${instance_url}/services/oauth2/singleaccess`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
      }
    );

    const singleData = await singleResp.json();

    if (!singleResp.ok) {
      log('❌ singleaccess KO:', singleResp.status, singleData);
      return res
        .status(500)
        .json({ error: 'singleaccess_failed', detail: singleData });
    }

    const frontdoorUrl =
      singleData.frontdoor_uri || singleData.frontdoorUrl;

    if (!frontdoorUrl) {
      log('⚠️ singleaccess sin frontdoor_uri:', singleData);
      return res
        .status(500)
        .json({ error: 'no_frontdoor_in_response', data: singleData });
    }

    log('✅ frontdoorUrl generado');
    res.json({frontdoorUrl, redirectUri: redirectUri || null});
    } catch (e) {
    log('💥 Error en /api/lo2/frontdoor:', e.message);
    res.status(500).json({ error: 'server_error', message: e.message });
  }
});

// ------------- Arrancar servidor ---------------------
app.listen(PORT, () => {
  log(`Servidor escuchando en puerto ${PORT}`);
});

app.get('/debug/frontdoor-open', async (req, res) => {
  try {
    const { access_token, instance_url } = await getAccessTokenFromRefresh();

    const body = new URLSearchParams({
      redirect_uri: '/lightning/page/home'
    });

    const singleResp = await fetch(`${instance_url}/services/oauth2/singleaccess`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    const singleData = await singleResp.json();

    if (!singleResp.ok) {
      log('❌ singleaccess KO:', singleResp.status, singleData);
      return res.status(500).json(singleData);
    }

    const frontdoorUrl = singleData.frontdoor_uri || singleData.frontdoorUrl;

    if (!frontdoorUrl) {
      return res.status(500).json({
        error: 'no_frontdoor_in_response',
        data: singleData
      });
    }

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.redirect(302, frontdoorUrl);
  } catch (e) {
    log('💥 Error en /debug/frontdoor-open:', e.message);
    res.status(500).send(e.message);
  }
});

// Endpoint que LO2 usará como frontdoor-url
// LO2 carga esta URL en el iframe → servidor genera OTP al instante → redirect
app.get('/api/lo2/session', async (req, res) => {
  try {
    const { access_token, instance_url } = await getAccessTokenFromRefresh();

    const body = new URLSearchParams({
      redirect_uri: req.query.redirect_uri || '/lightning/page/home'
    });

    const singleResp = await fetch(`${instance_url}/services/oauth2/singleaccess`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    const singleData = await singleResp.json();

    if (!singleResp.ok) {
      return res.status(500).json(singleData);
    }

    const frontdoorUrl = singleData.frontdoor_uri || singleData.frontdoorUrl;

    if (!frontdoorUrl) {
      return res.status(500).json({ error: 'no_frontdoor_in_response', data: singleData });
    }

    // Headers anti-caché para que nunca se reutilice un OTP
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.redirect(302, frontdoorUrl);

  } catch (e) {
    log('💥 Error en /api/lo2/session:', e.message);
    res.status(500).send(e.message);
  }
});