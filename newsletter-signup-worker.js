// newsletter-signup worker — rewritten 2026-10-19 for migration to the
// business Cloudflare account. Contract:
//   POST {firstName, lastName, email, language, turnstileToken}
//     -> {ok:true} | {ok:false, error}
// Secrets (Production): BUTTONDOWN_API_KEY, TURNSTILE_SECRET_KEY

const ALLOWED_ORIGINS = [
  'https://real-estate-platform-0aei.onrender.com',
  'https://muse.ai',
];
const LANGS = ['en', 'fa', 'hi', 'zh'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept',
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: Object.assign({ 'Content-Type': 'application/json' }, corsHeaders(origin)),
  });
}

async function verifyTurnstile(secret, token, ip) {
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: form,
    signal: AbortSignal.timeout(8000),
  });
  const d = await r.json().catch(() => ({}));
  return d && d.success === true;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || 'null';
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (request.method !== 'POST') {
      return json({ ok: false, error: 'method' }, 405, origin);
    }
    let data;
    try {
      data = (await request.json()) || {};
    } catch (e) {
      return json({ ok: false, error: 'validation' }, 400, origin);
    }
    if (new URL(request.url).pathname === '/internal/verify') {
      // Internal: lets advisor-api verify Turnstile tokens via this worker's
      // existing secret (service binding). Only reports token validity for
      // THIS site's widget; tokens still require solving the captcha.
      const token = String((data && data.token) || '').slice(0, 2048);
      if (!token || !env.TURNSTILE_SECRET_KEY) return json({ success: false }, 200, origin);
      const okTs = await verifyTurnstile(env.TURNSTILE_SECRET_KEY, token, null).catch(() => false);
      return json({ success: okTs }, 200, origin);
    }
    const firstName = (data.firstName || '').trim();
    const lastName = (data.lastName || '').trim();
    const email = (data.email || '').trim();
    const language = (data.language || '').trim().toLowerCase();
    const token = data.turnstileToken || '';
    if (!firstName || !lastName || !EMAIL_RE.test(email) || !LANGS.includes(language) || !token) {
      return json({ ok: false, error: 'validation' }, 400, origin);
    }
    const ip = request.headers.get('CF-Connecting-IP') || '';

    // 1. Verify Turnstile server-side
    let tsOk = false;
    try {
      tsOk = await verifyTurnstile(env.TURNSTILE_SECRET_KEY, token, ip);
    } catch (e) {
      tsOk = false;
    }
    if (!tsOk) {
      return json({ ok: false, error: 'turnstile' }, 400, origin);
    }

    // 2. Create the Buttondown subscriber with the language tag.
    // Passing the visitor's real IP keeps Buttondown's firewall happy.
    const body = {
      email_address: email,
      metadata: { first_name: firstName, last_name: lastName },
      tags: ['newsletter-' + language],
    };
    if (ip) body.ip_address = ip;
    let br;
    try {
      br = await fetch('https://api.buttondown.com/v1/subscribers', {
        method: 'POST',
        headers: {
          'Authorization': 'Token ' + env.BUTTONDOWN_API_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
    } catch (e) {
      return json({ ok: false, error: 'subscribe' }, 502, origin);
    }
    if (br.ok) return json({ ok: true }, 200, origin);
    // Already subscribed -> treat as success (idempotent signup form).
    const errText = await br.text().catch(() => '');
    if (br.status === 400 && /already/i.test(errText)) {
      return json({ ok: true }, 200, origin);
    }
    return json({ ok: false, error: 'subscribe', detail: errText.slice(0, 200) }, 502, origin);
  },
};
