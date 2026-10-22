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
    'Vary': 'Origin',
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
  return d || {};
}
const TS_HOSTS = ['real-estate-platform-0aei.onrender.com', 'muse.ai'];
function tsPassed(d) {
  return !!(d && d.success === true && (!d.hostname || TS_HOSTS.includes(d.hostname)));
}
async function safeEq(a, b) {
  // Hash-then-compare in constant time (no length or prefix leak).
  const enc = new TextEncoder();
  const x = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(a || ''))));
  const y = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(b || ''))));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
function str(v, max) {
  return (typeof v === 'string' ? v.trim() : '').slice(0, max);
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
    // Public-path hygiene: a present-but-foreign Origin or a non-JSON body is
    // rejected outright (service-binding calls carry no Origin header).
    const rawOrigin = request.headers.get('Origin');
    if (rawOrigin && !ALLOWED_ORIGINS.includes(rawOrigin)) {
      return json({ ok: false, error: 'origin' }, 403, origin);
    }
    if (!(request.headers.get('Content-Type') || '').includes('application/json')) {
      return json({ ok: false, error: 'validation' }, 415, origin);
    }
    let data;
    try {
      const rawBody = await request.text();
      if (rawBody.length > 8192) return json({ ok: false, error: 'validation' }, 413, origin);
      data = JSON.parse(rawBody) || {};
      if (typeof data !== 'object' || Array.isArray(data)) throw new Error('shape');
    } catch (e) {
      return json({ ok: false, error: 'validation' }, 400, origin);
    }
    const reqUrl = new URL(request.url);
    if (reqUrl.pathname === '/internal/verify') {
      // Internal: lets advisor-api verify Turnstile tokens via this worker's
      // existing secret (service binding). Only reports token validity for
      // THIS site's widget; tokens still require solving the captcha.
      // Gate (cycle 9): binding calls arrive with the placeholder host
      // 'newsletter.internal', which public traffic can never present; any
      // other caller must present the shared secret header.
      if (reqUrl.hostname !== 'newsletter.internal') {
        const given = request.headers.get('X-Internal-Secret') || '';
        if (!env.INTERNAL_SECRET || !(await safeEq(given, env.INTERNAL_SECRET))) {
          return new Response('Not found', { status: 404 });
        }
      }
      const token = String((data && data.token) || '').slice(0, 2048);
      if (!token || !env.TURNSTILE_SECRET_KEY) return json({ success: false }, 200, origin);
      const d = await verifyTurnstile(env.TURNSTILE_SECRET_KEY, token, null).catch(() => ({}));
      return json({ success: tsPassed(d) }, 200, origin);
    }
    // Rate limit (Workers Rate Limiting binding, when provisioned):
    // 5 subscribe attempts / minute / IP, before any Turnstile spend.
    const ip = request.headers.get('CF-Connecting-IP') || '';
    if (env.RL) {
      const rl = await env.RL.limit({ key: 'sub:' + (ip || 'none') }).catch(() => ({ success: true }));
      if (!rl.success) return json({ ok: false, error: 'rate' }, 429, origin);
    }
    const firstName = str(data.firstName, 100).replace(/[\u0000-\u001f\u007f]/g, '');
    const lastName = str(data.lastName, 100).replace(/[\u0000-\u001f\u007f]/g, '');
    const email = str(data.email, 254);
    const language = str(data.language, 5).toLowerCase();
    const token = str(data.turnstileToken, 2048);
    if (!firstName || !lastName || !EMAIL_RE.test(email) || !LANGS.includes(language) || !token) {
      return json({ ok: false, error: 'validation' }, 400, origin);
    }
    // 1. Verify Turnstile server-side
    let tsOk = false;
    try {
      tsOk = tsPassed(await verifyTurnstile(env.TURNSTILE_SECRET_KEY, token, ip));
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
    // Classify upstream errors server-side only; the client never sees
    // Buttondown's text (it leaked list state and key problems — cycle 9).
    const errText = await br.text().catch(() => '');
    console.error('buttondown', br.status, errText.slice(0, 500));
    let code = '';
    try { code = String(JSON.parse(errText).code || ''); } catch (e) {}
    // Already subscribed -> treat as success (idempotent signup form).
    if (br.status === 409 || /already/i.test(code)) {
      return json({ ok: true }, 200, origin);
    }
    return json({ ok: false, error: 'subscribe' }, 502, origin);
  },
};
