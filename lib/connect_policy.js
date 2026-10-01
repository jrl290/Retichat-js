/**
 * What a page's Content-Security-Policy lets it connect to (connect-src),
 * for Settings and for the page as it loads: an exchange URL the policy does
 * not allow is refused when it is entered, with the reason
 * (App._saveSettings), and one saved before that check (or edited in
 * storage) is found before the page connects and said where the connection
 * status is shown (RnsClient.connect, App._applyStatusDot). Used, it would
 * leave the page offline with nothing to say why: the browser refuses every
 * request to it before it is sent, and PostInterface sees only a failed
 * fetch.
 *
 * The policy is not restated here. The page reads the header it is served
 * with (PagePolicy in app.js: a GET of its own URL, not cached), which the
 * nodes build from .htaccess, so the two cannot drift; a page served with
 * no policy (a local server) refuses nothing. exchange_url_policy.test.mjs
 * runs these rules against the .htaccess line itself.
 *
 * The matching is CSP Level 3's ("Does url match source list in origin",
 * §6.7.2.5 to §6.7.2.12), for the expressions a connect-src can hold:
 * 'self', 'none', *, a scheme ("https:") and a host source
 * ([scheme://]host[:port][/path], host with a leading "*." wildcard).
 * Keywords, nonces and hashes match no URL. Redirects are not followed
 * here, so a path always counts.
 */

/** The PostInterface requests an exchange at `base` makes
 *  (lib/rns/interfaces/post_interface.js: the base with any trailing "/"
 *  removed, then the path). */
export const EXCHANGE_PATHS = ["/v1/interfaces/register", "/v1/interfaces/exchange", "/v1/interfaces/goodbye"];

const DEFAULT_PORTS = { "http:": "80", "https:": "443", "ws:": "80", "wss:": "443", "ftp:": "21" };

/**
 * The connect-src source lists of a Content-Security-Policy header value:
 * one list per policy in it (policies are separated by ",", as a fetch's
 * Headers joins repeated header lines) that restricts connections, from
 * its connect-src or, without one, its default-src (the first of a
 * repeated directive counts, as CSP parses it). A URL is allowed only when
 * every list allows it. No header, or no policy that restricts
 * connections: an empty array, which allows everything.
 * @returns {string[][]}
 */
export function connectSourceLists(header) {
    if (typeof header !== "string" || !header.trim()) return [];
    const lists = [];
    for (const policy of header.split(",")) {
        const directives = new Map();
        for (const part of policy.split(";")) {
            const tokens = part.trim().split(/[\t\n\f\r ]+/).filter(Boolean);
            if (!tokens.length) continue;
            const name = tokens[0].toLowerCase();
            if (!directives.has(name)) directives.set(name, tokens.slice(1));
        }
        const sources = directives.get("connect-src") ?? directives.get("default-src");
        if (sources) lists.push(sources);
    }
    return lists;
}

/** CSP3 scheme-part match: expression scheme `a` against URL scheme `b`
 *  (both without the ":"), including the upgrades it allows. */
function schemeMatches(a, b) {
    a = a.toLowerCase();
    b = b.toLowerCase();
    return a === b || (a === "http" && b === "https") || (a === "ws" && ["wss", "http", "https"].includes(b))
        || (a === "wss" && b === "https");
}

/** CSP3 path-part match: an expression path ending in "/" is a prefix of
 *  segments, any other must equal the URL's path; segments compared
 *  percent-decoded. */
function pathMatches(exprPath, urlPath) {
    if (!exprPath) return true;
    if (exprPath === "/" && !urlPath) return true;
    const exact = !exprPath.endsWith("/");
    const decode = (seg) => { try { return decodeURIComponent(seg); } catch { return seg; } };
    const a = exprPath.split("/");
    const b = urlPath.split("/");
    if (!exact) a.pop();
    if (a.length > b.length) return false;
    if (exact && a.length !== b.length) return false;
    return a.every((seg, i) => decode(seg) === decode(b[i]));
}

const HOST_SOURCE = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|\*\.[^:/]+|[^:/*]+)(?::(\d+|\*))?(\/[^?#]*)?$/i;

/** Whether one source expression allows `url` (a URL) on a page at
 *  `self` (a URL). */
function expressionAllows(expr, url, self) {
    const scheme = url.protocol.slice(0, -1);
    if (expr === "*") {
        // CSP3: an HTTP(S) or WebSocket scheme, or the page's own.
        return ["http", "https", "ws", "wss"].includes(scheme) || url.protocol === self.protocol;
    }
    if (expr.toLowerCase() === "'self'") {
        // CSP3 §6.7.2.8: the page's origin, or its host with the same (or
        // both default) ports over https/wss, or http/ws from an http page.
        if (url.origin === self.origin) return true;
        if (url.hostname !== self.hostname) return false;
        if (url.port !== self.port) return false;           // "" is the scheme's default port (WHATWG URL)
        return ["https", "wss"].includes(scheme) || (self.protocol === "http:" && ["http", "ws"].includes(scheme));
    }
    if (expr.startsWith("'")) return false;               // keywords, nonces and hashes match no URL
    if (/^[a-z][a-z0-9+.-]*:$/i.test(expr)) return schemeMatches(expr.slice(0, -1), scheme);
    const m = HOST_SOURCE.exec(expr);
    if (!m) return false;
    const [, exprScheme, exprHost, exprPort, exprPath] = m;
    if (exprScheme ? !schemeMatches(exprScheme, scheme) : !schemeMatches(self.protocol.slice(0, -1), scheme)) return false;
    const host = url.hostname.toLowerCase();
    const want = exprHost.toLowerCase();
    if (want === "*") {
        // only "*" alone is a host wildcard
    } else if (want.startsWith("*.")) {
        if (!host.endsWith(want.slice(1))) return false;
    } else if (host !== want) {
        return false;
    }
    // CSP3 port-part match. WHATWG URL gives "" for the scheme's default
    // port: no port in the expression matches only that; a port matches
    // itself, and the default port of the URL's scheme when the URL has
    // none.
    if (exprPort !== "*") {
        const port = exprPort ?? "";
        if (port !== url.port && !(url.port === "" && port === DEFAULT_PORTS[url.protocol])) return false;
    }
    return pathMatches(exprPath ?? "", url.pathname);
}

/** Whether a source list allows `url` on a page at `self`. A list that is
 *  exactly 'none', or empty, allows nothing. */
export function sourceListAllows(sources, url, self) {
    const list = sources.filter((s) => s.toLowerCase() !== "'none'");
    return list.some((expr) => expressionAllows(expr, url, self));
}

/** How a source is named to the user: 'self' as this page's own origin. */
function describe(expr, self) {
    return expr.toLowerCase() === "'self'" ? `this page's own origin (${self.origin})` : expr;
}

/**
 * Why the page at `pageUrl`, served with Content-Security-Policy `header`
 * (null: none), cannot use the exchange at `exchangeUrl`, or null when it
 * can: each request PostInterface makes there (EXCHANGE_PATHS, resolved
 * against the page as fetch resolves them) must be allowed by every policy
 * that restricts connections. The reason names what the policy allows; it
 * says nothing of saving, which is the caller's to add (PagePolicy).
 * @returns {string|null}
 */
export function exchangeUrlRefusal(exchangeUrl, header, pageUrl) {
    const self = new URL(pageUrl);
    const base = String(exchangeUrl ?? "").trim().replace(/\/$/, "");
    let urls, shown;
    try {
        urls = EXCHANGE_PATHS.map((path) => new URL(base + path, self));
        shown = new URL(base, self).href;
    } catch {
        return `"${exchangeUrl}" is not a URL.`;
    }
    for (const sources of connectSourceLists(header)) {
        if (urls.every((url) => sourceListAllows(sources, url, self))) continue;
        const allowed = sources.filter((s) => s.toLowerCase() !== "'none'").map((s) => describe(s, self));
        return `This page's Content-Security-Policy lets it connect only to ${allowed.length ? allowed.join(", ") : "nothing"}. `
            + `The exchange ${shown} is not among them, so the browser would refuse every request to it and the page `
            + `would stay offline.`;
    }
    return null;
}
