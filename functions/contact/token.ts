import { formToken, turnstileSiteKey, type Env } from "../../lib/guard";

/**
 * GET /contact/token: a fresh signed form token, plus the Turnstile site key when it's configured.
 * The page is static and cached, so the form fetches its token here instead of having it rendered in.
 */
export const onRequestGet: PagesFunction<Env> = async ({ env }) => {
	try {
		return Response.json(
			{ t: await formToken(env), siteKey: turnstileSiteKey(env) },
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (err) {
		console.error("contact token failed", err);
		return Response.json({ error: "unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
	}
};
