/**
 * Spam protection for the contact form, ported from craigzielinski.com's newsletter signup
 * (craig-zielinski repo, SIGNUP-PROTECTION.md). Checks, cheapest first:
 *
 *   1. Origin header must be the site's own origin
 *   2. Honeypot field "website" must be empty
 *   3. Email format
 *   4. Signed form token "t" (fetched from /contact/token), form open 3 s to 24 h
 *   5. Cloudflare Turnstile (enforced only when both keys are set)
 *   6. Send limits in D1: per IP per hour, per sender address per day, site-wide per day
 *
 * There is no double opt-in: messages go to ops@, never to the address typed in the form.
 */

export interface Env {
	DB: D1Database;
	CONTACT_SECRET?: string; // secret: HMAC key for form tokens
	RESEND_API_KEY?: string; // secret
	TURNSTILE_SITE_KEY?: string; // var (public)
	TURNSTILE_SECRET_KEY?: string; // secret
	CONTACT_TO?: string; // var
	CONTACT_FROM?: string; // var: must be on a domain verified in Resend
}

const PER_IP_PER_HOUR = 3;
const PER_EMAIL_PER_DAY = 3;
// Resend's free plan allows 100 emails a day across the account, shared with the
// craigzielinski.com newsletter (capped at 40), Project MARTAC and Respec Training sign-in
// emails, so keep this small.
const DAILY_CAP = 15;

const HOUR_MS = 60 * 60 * 1000;
const FORM_MIN_AGE_MS = 3_000;
const FORM_MAX_AGE_MS = 24 * HOUR_MS;
const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]{2,}$/;
const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

function secret(env: Env): string {
	if (!env.CONTACT_SECRET) throw new Error("CONTACT_SECRET is not set");
	return env.CONTACT_SECRET;
}

export function normaliseEmail(input: unknown): string | null {
	if (typeof input !== "string") return null;
	const email = input.trim().toLowerCase();
	return email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

const b64url = (bytes: ArrayBuffer) =>
	btoa(String.fromCharCode(...new Uint8Array(bytes)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");

async function sign(key: string, message: string): Promise<string> {
	const k = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return b64url(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(message)));
}

function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

/** Signed timestamp the page fetches and puts in the form, so a POST proves the form was loaded, and when. */
export async function formToken(env: Env, now = Date.now()): Promise<string> {
	const ts = String(now);
	return `${ts}.${await sign(secret(env), `contact\n${ts}`)}`;
}

/** "ok", "too-fast" (form open under 3 s), or "invalid" (missing, forged or older than a day). */
export async function checkFormToken(env: Env, token: unknown, now = Date.now()): Promise<"ok" | "too-fast" | "invalid"> {
	if (typeof token !== "string") return "invalid";
	const [ts = "", sig = ""] = token.split(".");
	if (!/^\d+$/.test(ts) || !timingSafeEqual(sig, await sign(secret(env), `contact\n${ts}`))) return "invalid";
	const age = now - Number(ts);
	if (age > FORM_MAX_AGE_MS || age < 0) return "invalid";
	return age < FORM_MIN_AGE_MS ? "too-fast" : "ok";
}

/** Site key to render the widget with, or null when Turnstile isn't configured. */
export function turnstileSiteKey(env: Env): string | null {
	return env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY ? env.TURNSTILE_SITE_KEY : null;
}

/** True when the widget's token checks out (or Turnstile isn't configured). */
export async function verifyTurnstile(env: Env, token: unknown, ip: string | null): Promise<boolean> {
	if (!turnstileSiteKey(env)) return true;
	if (typeof token !== "string" || !token || token.length > 2048) return false;
	const body = new FormData();
	body.set("secret", env.TURNSTILE_SECRET_KEY!);
	body.set("response", token);
	if (ip) body.set("remoteip", ip);
	const res = await fetch(SITEVERIFY, { method: "POST", body });
	const outcome = (await res.json().catch(() => ({}))) as { success?: boolean; "error-codes"?: string[] };
	if (!outcome.success) console.warn("turnstile rejected", outcome["error-codes"]);
	return outcome.success === true;
}

async function sha256(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type LimitResult = "send" | "repeat" | "limited";

/** Decide whether to send; logs the send (hashed email and IP only) when the answer is "send". */
export async function checkLimits(env: Env, email: string, ip: string, now = Date.now()): Promise<LimitResult> {
	const db = env.DB;
	const [emailHash, ipHash] = await Promise.all([sha256(email), sha256(ip)]);
	const dayStart = new Date(now).toISOString().slice(0, 10) + "T00:00:00.000Z";
	const [byEmail, byIp, today] = await db.batch<{ n: number }>([
		db
			.prepare("SELECT COUNT(*) AS n FROM gs_contact_log WHERE email_hash = ? AND created_at > ?")
			.bind(emailHash, new Date(now - 24 * HOUR_MS).toISOString()),
		db
			.prepare("SELECT COUNT(*) AS n FROM gs_contact_log WHERE ip_hash = ? AND created_at > ?")
			.bind(ipHash, new Date(now - HOUR_MS).toISOString()),
		db.prepare("SELECT COUNT(*) AS n FROM gs_contact_log WHERE created_at >= ?").bind(dayStart),
	]);
	if ((byIp.results[0]?.n ?? 0) >= PER_IP_PER_HOUR || (today.results[0]?.n ?? 0) >= DAILY_CAP) return "limited";
	if ((byEmail.results[0]?.n ?? 0) >= PER_EMAIL_PER_DAY) return "repeat";
	await db
		.prepare("INSERT INTO gs_contact_log (email_hash, ip_hash, created_at) VALUES (?, ?, ?)")
		.bind(emailHash, ipHash, new Date(now).toISOString())
		.run();
	return "send";
}

/** Send the message to ops@ through Resend, with the visitor's address as reply-to. */
export async function sendMessage(
	env: Env,
	msg: { name: string; email: string; message: string; country: string | null },
): Promise<void> {
	if (!env.RESEND_API_KEY || !env.CONTACT_TO || !env.CONTACT_FROM) {
		throw new Error("Contact form is not configured (RESEND_API_KEY, CONTACT_TO, CONTACT_FROM)");
	}
	const text = [
		`From: ${msg.name} <${msg.email}>`,
		msg.country ? `Country: ${msg.country}` : null,
		"",
		msg.message,
		"",
		"-- Sent from the contact form on glasgowshipyard.com. Reply to answer.",
	]
		.filter((line) => line !== null)
		.join("\n");
	const res = await fetch("https://api.resend.com/emails", {
		method: "POST",
		headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
		body: JSON.stringify({
			from: env.CONTACT_FROM,
			to: [env.CONTACT_TO],
			reply_to: msg.email,
			subject: `Glasgow Shipyard contact: ${msg.name}`,
			text,
		}),
	});
	if (!res.ok) throw new Error(`Resend ${res.status}: ${(await res.text()).slice(0, 300)}`);
}
