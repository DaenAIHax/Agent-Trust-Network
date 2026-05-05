import type { APIRoute } from 'astro';
import { AMBASSADOR_URL } from '../../../lib/server/config';
import { logEvent } from '../../../lib/server/logger';

export const prerender = false;

/**
 * GET /api/session/whoami
 *
 * Pure passthrough to the Ambassador. After ADR-019 Phase 8b-2a both
 * single mode (cullis_connector/ambassador/session_routes.py) and
 * shared mode (cullis_connector/ambassador/shared/router.py) return
 * the same ADR-020 wrapped shape:
 *
 *   { ok, principal: { spiffe_id, principal_type, name, org,
 *                      trust_domain, sub, source },
 *     principal_id, sub, org, exp }
 *
 * The SPA's `lib/api.ts:whoami()` consumes that wrapped shape directly
 * — no translation here. This Astro route stays only to pass cookies
 * through in the dev `npm run dev` topology and the Frontdesk
 * container Phase 7 nginx config; Phase 8b-2 will remove it entirely
 * along with switching Astro to static.
 */
export const GET: APIRoute = async ({ request }) => {
  const fwdHeaders: Record<string, string> = {};
  const fwdCookie = request.headers.get('cookie');
  if (fwdCookie) {
    fwdHeaders.Cookie = fwdCookie;
  }

  try {
    const upstream = await fetch(`${AMBASSADOR_URL}/api/session/whoami`, {
      method: 'GET',
      headers: fwdHeaders,
    });
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    logEvent('whoami_upstream_error', { reason });
    return new Response(
      JSON.stringify({ ok: false, error: 'upstream_unreachable' }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    );
  }
};
