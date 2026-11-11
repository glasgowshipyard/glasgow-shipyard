import { checkFormToken, checkLimits, normaliseEmail, sendMessage, verifyTurnstile, type Env } from "../../lib/guard";

/**
 * POST /contact: checks run cheapest first (see lib/guard.ts). Replies with JSON {s}:
 *   sent     message sent, or a bot was caught (bots get the same answer and learn nothing)
 *   invalid  email doesn't look right
 *   missing  name or message empty
 *   retry    submitted under 3 s after the form loaded
 *   verify   Turnstile failed
 *   busy     IP or daily limit reached
 *   error    something broke on our side
 */
type Status = "sent" | "invalid" | "missing" | "retry" | "verify" | "busy" | "error";

const reply = (s: Status) => Response.json({ s }, { headers: { "Cache-Control": "no-store" } });

const field = (form: FormData, name: string, max: number) => {
	const value = form.get(name);
	return typeof value === "string" ? value.trim().slice(0, max) : "";
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
	// 1. Browsers send Origin on POSTs; scripts posting from elsewhere don't match it.
	if (request.headers.get("Origin") !== new URL(request.url).origin) return reply("sent");
	const form = await request.formData().catch(() => null);
	// 2. Honeypot: real people never fill the hidden "website" field.
	if (!form || form.get("website")) return reply("sent");
	// 3. Email format, and the other fields.
	const email = normaliseEmail(form.get("email"));
	if (!email) return reply("invalid");
	const name = field(form, "name", 100).replace(/[\r\n]+/g, " ");
	const message = field(form, "message", 5000);
	if (!name || !message) return reply("missing");
	try {
		// 4. Signed token: scripts that never load the page don't have one.
		const token = await checkFormToken(env, form.get("t"));
		if (token === "invalid") return reply("sent");
		if (token === "too-fast") return reply("retry");
		// 5. Turnstile.
		const ip = request.headers.get("CF-Connecting-IP");
		if (!(await verifyTurnstile(env, form.get("cf-turnstile-response"), ip))) return reply("verify");
		// 6. Send limits. A repeat sender over the per-address limit gets "sent" without an email.
		const verdict = await checkLimits(env, email, ip ?? "unknown");
		if (verdict === "limited") return reply("busy");
		if (verdict === "send") {
			const country = (request as { cf?: { country?: string } }).cf?.country ?? null;
			await sendMessage(env, { name, email, message, country });
		}
	} catch (err) {
		console.error("contact failed", err);
		return reply("error");
	}
	return reply("sent");
};
