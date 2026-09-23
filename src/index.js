export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // ============================================================
    // ROUTE 1: GET /?id=PASTE_ID  → proxy a raw Pastebin paste
    // ============================================================
    if (request.method === "GET" && url.searchParams.has("id")) {
      const pasteId = url.searchParams.get("id");
      const pastebinUrl = `https://pastebin.com/raw/${encodeURIComponent(pasteId)}`;
      const res = await fetch(pastebinUrl, {
        headers: { "User-Agent": "Cloudflare-Worker-Pastebin-Proxy/1.0" },
      });
      const text = await res.text();
      return new Response(text, {
        status: res.status,
        headers: {
          ...corsHeaders,
          "Content-Type": "text/plain;charset=UTF-8",
          "Cache-Control": "public, max-age=60",
        },
      });
    }

    // ============================================================
    // ROUTE 2: POST /create  → create a new Pastebin paste
    // ============================================================
    if (request.method === "POST" && url.pathname === "/create") {
      try {
        const body = await request.json();
        const { content, title = "", expire = "N", format = "text", private: priv = "0" } = body;
        if (!content) {
          return json({ error: "Missing content" }, 400, corsHeaders);
        }

        const params = new URLSearchParams();
        params.append("api_dev_key", env.PASTEBIN_DEV_KEY);
        if (env.PASTEBIN_USER_KEY) params.append("api_user_key", env.PASTEBIN_USER_KEY);
        params.append("api_option", "create");
        params.append("api_paste_code", content);
        params.append("api_paste_name", title);
        params.append("api_paste_expire_date", expire);
        params.append("api_paste_format", format);
        params.append("api_paste_private", priv);

        const apiRes = await fetch("https://pastebin.com/api/api_post.php", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: params.toString(),
        });
        const resultText = await apiRes.text();

        if (!apiRes.ok || resultText.startsWith("Bad API request")) {
          return json({ error: resultText }, 400, corsHeaders);
        }

        return json({ success: true, url: resultText }, 200, corsHeaders);
      } catch (err) {
        return json({ error: err.message }, 500, corsHeaders);
      }
    }

    // ============================================================
    // ROUTE 3: POST /verify  → verify Linkvertise hash, issue key
    //   Body: { hash: "..." }
    // ============================================================
    if (request.method === "POST" && url.pathname === "/verify") {
      try {
        const { hash } = await request.json();

        if (!hash || !/^[A-Za-z0-9]{64}$/.test(hash)) {
          return json({
            success: false,
            error: "Missing or malformed hash",
            debug_received: hash ?? null,
            debug_length: hash ? String(hash).length : 0,
            debug_type: typeof hash,
          }, 400, corsHeaders);
        }

        const ip = request.headers.get("CF-Connecting-IP") || "unknown";

        // Rate limit: 1 key per IP per 10 min (only if DB is bound)
        if (env.DB) {
          const recent = await env.DB.prepare(
            "SELECT created_at FROM issued WHERE ip = ? ORDER BY created_at DESC LIMIT 1"
          ).bind(ip).first();

          if (recent && Date.now() - recent.created_at < 10 * 60 * 1000) {
            return json(
              { success: false, error: "Please wait before requesting another key." },
              429,
              corsHeaders
            );
          }
        }

        // Ask Linkvertise whether this hash completed the flow
        const verified = await verifyLinkvertise(env, hash);
        if (!verified) {
          return json(
            { success: false, error: "Sponsor step not verified. Complete it and try again." },
            403,
            corsHeaders
          );
        }

        // Generate key
        const key = generateKey();

        // Store in D1 (if bound)
        if (env.DB) {
          await env.DB.prepare(
            "INSERT INTO issued (ip, key, hash, created_at) VALUES (?, ?, ?, ?)"
          ).bind(ip, key, hash, Date.now()).run();
        }

        return json({ success: true, key }, 200, corsHeaders);
      } catch (err) {
        return json({ success: false, error: err.message }, 500, corsHeaders);
      }
    }

    // ============================================================
    // ROUTE 4: Everything else → serve static files from /public
    // ============================================================
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not found", { status: 404, headers: corsHeaders });
  },
};

// ============================================================
// HELPERS
// ============================================================

function json(obj, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function generateKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1
  const seg = () =>
    Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `STORM-${seg()}-${seg()}-${seg()}`;
}

async function verifyLinkvertise(env, hash) {
  const token = env.LINKVERTISE_ANTI_BYPASS_TOKEN;
  if (!token) throw new Error("LINKVERTISE_ANTI_BYPASS_TOKEN not configured");

  const verifyUrl =
    `https://publisher.linkvertise.com/api/v1/anti_bypassing` +
    `?token=${encodeURIComponent(token)}&hash=${encodeURIComponent(hash)}`;

  const res = await fetch(verifyUrl, { method: "POST" });
  if (!res.ok) return false;

  const text = (await res.text()).trim();
  return text === "TRUE";
}