/**
 * Cloudflare Pages Function — AI Track 2025 closing-report intake.
 *
 * Receives the form's JSON POST and relays it as an email via the Resend API.
 * The page also keeps a mailto fallback, so this endpoint failing never loses a report.
 *
 * Required environment variables (Cloudflare Pages → Settings → Variables):
 *   RESEND_API_KEY   secret  — your Resend API key.
 *   RESEND_FROM      var     — verified sender, e.g. "EPFL AI Track <reports@yourdomain>".
 * Optional:
 *   REPORT_TO        var     — recipient (defaults to marius.conti@epfl.ch).
 *   TURNSTILE_SECRET secret  — set this only if you enable Cloudflare Turnstile on the page.
 *
 * Spam protection: a honeypot field ("website") is always checked. If TURNSTILE_SECRET
 * is set, the Turnstile token is verified too; if it is unset, Turnstile is skipped.
 */

const DEFAULT_TO = "marius.conti@epfl.ch";

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function verifyTurnstile(secret, token, ip) {
  if (!token) return false;
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    const data = await res.json();
    return !!data.success;
  } catch {
    return false;
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "Bad request" }, 400);
  }

  // Honeypot: bots fill the hidden "website" field; humans never do.
  // Accept silently so we don't tip off the bot, but don't send anything.
  if (data && typeof data.website === "string" && data.website.trim() !== "") {
    return json({ ok: true });
  }

  const subject = (data.subject || "").toString().slice(0, 300).trim();
  const body = (data.body || "").toString();
  const replyTo = (data.replyTo || "").toString().slice(0, 200).trim();

  if (!body || body.length < 20) return json({ error: "Empty submission" }, 400);
  if (body.length > 60000) return json({ error: "Submission too long" }, 413);

  if (env.TURNSTILE_SECRET) {
    const ok = await verifyTurnstile(
      env.TURNSTILE_SECRET,
      data.token,
      request.headers.get("CF-Connecting-IP")
    );
    if (!ok) return json({ error: "Verification failed" }, 403);
  }

  if (!env.RESEND_API_KEY || !env.RESEND_FROM) {
    return json({ error: "Server not configured" }, 500);
  }

  const payload = {
    from: env.RESEND_FROM,
    to: [env.REPORT_TO || DEFAULT_TO],
    subject: subject || "AI Track 2025 — Closing report",
    text: body,
  };
  if (replyTo && /.+@.+\..+/.test(replyTo)) payload.reply_to = replyTo;

  let res;
  try {
    res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + env.RESEND_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  } catch {
    return json({ error: "Send failed" }, 502);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    return json({ error: "Send failed", detail: detail.slice(0, 300) }, 502);
  }

  return json({ ok: true });
}
