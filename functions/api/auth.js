export async function onRequestPost({ request, env }) {
  try {
    const { initData } = await request.json();
    if (!initData) return json({ error: "Missing initData" }, 400);
    if (!env.BOT_TOKEN) return json({ error: "Server misconfigured" }, 500);

    const tgUser = await validateInitData(initData, env.BOT_TOKEN);
    if (!tgUser) return json({ error: "Invalid initData" }, 401);

    const telegramId = tgUser.id;
    const email = `tg${telegramId}@telegram.local`;
    const password = await derivePassword(telegramId, env.AUTH_PASSWORD_SECRET);

    let session = await signIn(env, email, password);
    if (!session) {
      const created = await createUser(env, email, password, tgUser);
      if (!created.ok) return json({ error: "create failed: " + created.error }, 500);
      session = await signIn(env, email, password);
      if (!session) return json({ error: "signin after create failed" }, 500);
    }

    await linkFamilyMember(env, telegramId, session.user.id);

    return json({
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: session.expires_at,
      user: { id: session.user.id, telegram_id: telegramId }
    });
  } catch (e) {
    return json({ error: e.message || "Unexpected error" }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function validateInitData(initData, botToken) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const enc = new TextEncoder();
  const k1 = await crypto.subtle.importKey(
    "raw", enc.encode("WebAppData"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const secret = await crypto.subtle.sign("HMAC", k1, enc.encode(botToken));

  const k2 = await crypto.subtle.importKey(
    "raw", secret,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k2, enc.encode(dataCheckString));
  const expected = [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, "0")).join("");

  if (expected.length !== hash.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ hash.charCodeAt(i);
  }
  if (diff !== 0) return null;

  const authDate = Number(params.get("auth_date"));
  if (!Number.isFinite(authDate)) return null;
  if (Date.now() / 1000 - authDate > 3600) return null;

  try {
    return JSON.parse(params.get("user") || "null");
  } catch {
    return null;
  }
}

async function derivePassword(telegramId, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`tg:${telegramId}`));
  return [...new Uint8Array(sig)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function signIn(env, email, password) {
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": env.SUPABASE_ANON_KEY
    },
    body: JSON.stringify({ email, password })
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.access_token ? data : null;
}

async function createUser(env, email, password, tgUser) {
  const res = await fetch(`${env.SUPABASE_URL}/auth/v1/admin/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
      "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
    },
    body: JSON.stringify({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        telegram_id: tgUser.id,
        first_name: tgUser.first_name || null,
        last_name: tgUser.last_name || null,
        username: tgUser.username || null
      }
    })
  });
  if (!res.ok) return { ok: false, error: await res.text() };
  return { ok: true };
}

async function linkFamilyMember(env, telegramId, userId) {
  const res = await fetch(
    `${env.SUPABASE_URL}/rest/v1/family_members?telegram_id=eq.${telegramId}&user_id=is.null`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Prefer": "return=minimal"
      },
      body: JSON.stringify({ user_id: userId })
    }
  );
  if (!res.ok) console.warn("linkFamilyMember:", res.status, await res.text());
}