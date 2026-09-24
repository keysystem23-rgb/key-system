export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token",
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
    // ROUTE 5: POST /validate  → check if a key exists in D1
    //   Body: { key: "STORM-XXXX-XXXX-XXXX" }
    //   Also accepts env.MASTER_KEY (bypasses D1 entirely)
    // ============================================================
    if (request.method === "POST" && url.pathname === "/validate") {
      try {
        const { key } = await request.json();
        if (!key || typeof key !== "string") {
          return json({ valid: false, error: "Missing key" }, 400, corsHeaders);
        }

        const trimmed = key.trim();

        // Master key check — bypasses D1 entirely
        if (env.MASTER_KEY && trimmed === env.MASTER_KEY) {
          return json({ valid: true, master: true }, 200, corsHeaders);
        }

        if (!env.DB) {
          return json({ valid: false, error: "DB not configured" }, 500, corsHeaders);
        }

        const row = await env.DB.prepare(
          "SELECT key FROM issued WHERE key = ? LIMIT 1"
        ).bind(trimmed).first();

        return json({ valid: !!row }, 200, corsHeaders);
      } catch (err) {
        return json({ valid: false, error: err.message }, 500, corsHeaders);
      }
    }

    // ============================================================
    // ROUTE 6: POST /track  → log user session info from Luau
    // ============================================================
    if (request.method === "POST" && url.pathname === "/track") {
      try {
        const body = await request.json();
        const {
          username = null,
          display_name = null,
          user_id = null,
          executor = null,
          account_age = null,
          key = null,
          hwid = null,
          place_id = null,
          game_id = null,
          elapsed_seconds = 0,
          is_start = false,
        } = body;

        if (!key || !hwid || place_id === null || game_id === null) {
          return json({ ok: false, error: "Missing required fields" }, 400, corsHeaders);
        }

        if (!env.DB) {
          return json({ ok: false, error: "DB not configured" }, 500, corsHeaders);
        }

        // Cloudflare provides these without any client input
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const country = (request.cf && request.cf.country) || "XX";

        const now = Date.now();
        const elapsed = Math.max(0, Math.floor(Number(elapsed_seconds) || 0));
        const executionDelta = is_start ? 1 : 0;

        // Normalize numeric fields (accept null cleanly)
        const userId = user_id === null || user_id === undefined ? null : Number(user_id);
        const accountAge = account_age === null || account_age === undefined ? null : Number(account_age);

        // UPSERT: insert new row, or increment existing one
        await env.DB.prepare(`
          INSERT INTO sessions
            (username, display_name, user_id, executor, account_age, ip, country, key_used, hwid,
             place_id, game_id, executions, total_seconds, first_seen, last_seen)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(key_used, hwid, place_id) DO UPDATE SET
            username      = COALESCE(excluded.username, sessions.username),
            display_name  = COALESCE(excluded.display_name, sessions.display_name),
            user_id       = COALESCE(excluded.user_id, sessions.user_id),
            executor      = COALESCE(excluded.executor, sessions.executor),
            account_age   = COALESCE(excluded.account_age, sessions.account_age),
            ip            = excluded.ip,
            country       = excluded.country,
            executions    = sessions.executions + ?,
            total_seconds = sessions.total_seconds + ?,
            last_seen     = excluded.last_seen
        `).bind(
          username, display_name, userId, executor, accountAge, ip, country, key, String(hwid),
          Number(place_id), Number(game_id),
          executionDelta, elapsed, now, now,
          executionDelta, elapsed
        ).run();

        return json({ ok: true }, 200, corsHeaders);
      } catch (err) {
        return json({ ok: false, error: err.message }, 500, corsHeaders);
      }
    }

    // ============================================================
    // ROUTE 7: GET /sessions  → view all logged sessions
    //   Requires ?token=ADMIN_TOKEN matching env.ADMIN_TOKEN
    // ============================================================
    if (request.method === "GET" && url.pathname === "/sessions") {
      const token = url.searchParams.get("token");
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) {
        return json({ error: "Unauthorized" }, 401, corsHeaders);
      }
      try {
        const { results } = await env.DB.prepare(
          "SELECT * FROM sessions ORDER BY last_seen DESC LIMIT 500"
        ).all();
        return json({ count: results.length, sessions: results }, 200, corsHeaders);
      } catch (err) {
        return json({ error: err.message }, 500, corsHeaders);
      }
    }

    // ============================================================
    // ROUTE 8: POST /admin/upload-lua?name=XXX  → store Lua in D1
    //   Header: X-Admin-Token: <ADMIN_TOKEN>
    //   Body: raw Lua source
    // ============================================================
    if (request.method === "POST" && url.pathname === "/admin/upload-lua") {
      const auth = request.headers.get("X-Admin-Token");
      if (!env.ADMIN_TOKEN || auth !== env.ADMIN_TOKEN) {
        return json({ error: "Unauthorized" }, 401, corsHeaders);
      }
      const name = url.searchParams.get("name");
      if (!name || !/^[A-Za-z0-9_-]{1,64}$/.test(name)) {
        return json({ error: "Invalid name" }, 400, corsHeaders);
      }
      const content = await request.text();
      if (!content || content.length < 10) {
        return json({ error: "Empty content" }, 400, corsHeaders);
      }
      if (content.length > 500_000) {
        return json({ error: "Too large (max 500 KB)" }, 413, corsHeaders);
      }
      if (!env.DB) {
        return json({ error: "DB not configured" }, 500, corsHeaders);
      }
      await env.DB.prepare(
        `INSERT INTO scripts (name, content, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(name) DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at`
      ).bind(name, content, Date.now()).run();
      return json({ ok: true, name, size: content.length }, 200, corsHeaders);
    }

    // ============================================================
    // ROUTE 9: GET /lua/:name?key=SCRIPT_TOKEN  → serve gated Lua
    //   Also logs the fetch to `downloads` (best-effort, non-blocking)
    // ============================================================
    if (request.method === "GET" && url.pathname.startsWith("/lua/")) {
      const name = url.pathname.slice(5);
      const key = url.searchParams.get("key");
      if (!env.SCRIPT_TOKEN || key !== env.SCRIPT_TOKEN) {
        return new Response("Not found", { status: 404, headers: corsHeaders });
      }
      if (!env.DB) {
        return new Response("Server error", { status: 500, headers: corsHeaders });
      }

      // Best-effort download log — never blocks or fails the response
      try {
        await env.DB.prepare(
          "INSERT INTO downloads (name, ip, country, ua, at) VALUES (?, ?, ?, ?, ?)"
        ).bind(
          name,
          request.headers.get("CF-Connecting-IP") || "unknown",
          (request.cf && request.cf.country) || "XX",
          request.headers.get("User-Agent") || "",
          Date.now()
        ).run();
      } catch (_) { /* ignore logging failures */ }

      const row = await env.DB.prepare(
        "SELECT content FROM scripts WHERE name = ?"
      ).bind(name).first();
      if (!row) {
        return new Response("Not found", { status: 404, headers: corsHeaders });
      }
      return new Response(row.content, {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "text/plain;charset=UTF-8",
          "Cache-Control": "no-store",
        },
      });
    }

    // ============================================================
    // ROUTE 10: GET /downloads?token=ADMIN_TOKEN  → view fetch log
    // ============================================================
    if (request.method === "GET" && url.pathname === "/downloads") {
      const token = url.searchParams.get("token");
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) {
        return json({ error: "Unauthorized" }, 401, corsHeaders);
      }
      try {
        const { results } = await env.DB.prepare(
          "SELECT * FROM downloads ORDER BY at DESC LIMIT 500"
        ).all();
        return json({ count: results.length, downloads: results }, 200, corsHeaders);
      } catch (err) {
        return json({ error: err.message }, 500, corsHeaders);
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