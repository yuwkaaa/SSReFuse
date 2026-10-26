<?php
/**
 * SSReFuse lab application (PHP, built-in server).
 *
 * A deliberately vulnerable image-and-link preview service, in the shape real
 * PHP applications take: one URL-fetching feature reached through several
 * routes, each with a different guard. Every route is bracketed by
 * @ssrefuse:begin/end markers so the corpus loader can attribute a
 * static-analysis finding to a labelled variant without hardcoding line
 * numbers.
 *
 * The app is standalone on purpose -- it includes nothing from the ssrefuse
 * package, so static analysers see ordinary application code.
 *
 * Why a PHP lab exists at all, beyond adding a third language: the guards
 * below are the same guards as the Python and JavaScript labs, and PHP answers
 * differently on two of them. Both differences were measured on 8.4.27 rather
 * than assumed.
 *
 *   parse_url() does not canonicalise the authority. '2130706433',
 *   '0177.0.0.1', '0x7f000001' and '127.1' all come back verbatim, where
 *   Node's URL() rewrites every one of them to '127.0.0.1'. A host denylist is
 *   therefore a different control in PHP than the same denylist in Node.
 *
 *   filter_var(..., NO_PRIV_RANGE|NO_RES_RANGE) calls 100.64.0.10 (CGNAT) and
 *   100.100.100.200 (Alibaba metadata) public, and calls 203.0.113.5 public
 *   where Python's ipaddress calls it private. A "resolve, then reject
 *   non-public" guard built on it has holes that the same guard in Python does
 *   not.
 *
 * Testbed facts the guards are written against:
 *   public.ssrefuse.test   -> 192.88.99.10      the partner host this app trusts
 *   internal.ssrefuse.test -> 127.0.0.1         internal admin service, port 19001
 *   metadata.ssrefuse.test -> 169.254.169.254   fake cloud metadata
 *   cgnat.ssrefuse.test    -> 100.64.0.10       RFC 6598 shared space
 */
declare(strict_types=1);

const ALLOWED_HOST = 'public.ssrefuse.test';
const ALLOWED_ORIGIN = 'http://public.ssrefuse.test';
const BLOCKED_SUBSTRINGS = ['127.0.0.1', 'localhost', '169.254.169.254'];
const BLOCKED_HOSTS = ['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0'];
const ALLOWED_PORTS = [80, 443];
const TIMEOUT = 4;

/** Ranges a correct guard has to reject, including the two filter_var misses. */
const PRIVATE_CIDRS = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.168.0.0/16', '100.100.100.200/32',
];

function send(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES), "\n";
}

function ok(string $text, int $status = 200): void
{
    send($status, ['fetched' => true, 'body' => $text]);
}

function blocked(string $why): void
{
    send(403, ['fetched' => false, 'blocked' => $why]);
}

/**
 * The fetch was attempted and the client library failed.
 *
 * Kept distinct from blocked() because collapsing the two is how an SSRF
 * matrix overstates a filter: a connection refused by the network is not a
 * guard that held.
 */
function sink_error(string $why): void
{
    send(502, ['fetched' => false, 'sink_error' => $why]);
}

function http_ctx(bool $follow = true): mixed
{
    return stream_context_create(['http' => [
        'timeout' => TIMEOUT, 'follow_location' => $follow ? 1 : 0,
        'ignore_errors' => true,
    ]]);
}

function in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    $ipLong = ip2long($ip);
    $netLong = ip2long($net);
    if ($ipLong === false || $netLong === false) {
        return false;
    }
    $mask = $bits === '0' ? 0 : (-1 << (32 - (int) $bits)) & 0xFFFFFFFF;
    return ($ipLong & $mask) === ($netLong & $mask);
}

// @ssrefuse:begin php-001
/**
 * No validation at all, on the sink the assignment names first.
 *
 * file_get_contents() with allow_url_fopen reaches every stream wrapper the
 * build has, so this route is not only an HTTP fetch: file://, php://filter
 * and data:// are all in range of the same call.
 */
function route_direct(): void
{
    $url = $_GET['url'] ?? '';
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-001

// @ssrefuse:begin php-002
/**
 * No validation, and the response body is discarded.
 *
 * Only the access log and the DNS log can see whether the fetch happened, so
 * this is the blind variant: the oracle is out-of-band, not the response.
 */
function route_blind(): void
{
    $url = $_GET['url'] ?? '';
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, TIMEOUT);
    $body = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        sink_error($err !== '' ? $err : 'curl_exec returned false');
        return;
    }
    send(202, ['fetched' => true, 'queued' => true]);
}
// @ssrefuse:end php-002

// @ssrefuse:begin php-003
/**
 * Rejects URLs whose raw text mentions a blocked address.
 *
 * The check never parses the URL, so any alternative spelling of the same
 * address walks straight through.
 */
function route_denylist_string(): void
{
    $url = $_GET['url'] ?? '';
    foreach (BLOCKED_SUBSTRINGS as $bad) {
        if (stripos($url, $bad) !== false) {
            blocked("denylisted substring $bad");
            return;
        }
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-003

// @ssrefuse:begin php-004
/**
 * Parses the URL and compares the hostname against a blocklist.
 *
 * This is the guard where PHP and Node diverge, and the divergence is the
 * whole point of the row: parse_url() hands back the authority as written, so
 * '2130706433', '0x7f000001' and '127.1' are not '127.0.0.1' as far as this
 * comparison is concerned. The identical guard written against Node's URL()
 * holds, because that parser rewrites them first.
 */
function route_denylist_host(): void
{
    $url = $_GET['url'] ?? '';
    $host = parse_url($url, PHP_URL_HOST);
    if ($host === false || $host === null) {
        blocked('unparsable url');
        return;
    }
    if (in_array(strtolower($host), BLOCKED_HOSTS, true)) {
        blocked("denylisted host $host");
        return;
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-004

// @ssrefuse:begin php-005
/**
 * Requires the URL to start with an allowlisted origin string.
 *
 * A prefix test says nothing about where the authority ends, so the
 * allowlisted name can be demoted to userinfo or carried in a longer name
 * that the attacker owns.
 */
function route_allow_prefix(): void
{
    $url = $_GET['url'] ?? '';
    if (!str_starts_with($url, ALLOWED_ORIGIN)) {
        blocked('url does not start with the allowed origin');
        return;
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-005

// @ssrefuse:begin php-006
/**
 * Restricts the scheme and checks nothing else.
 *
 * This closes the wrapper surface that makes file_get_contents interesting --
 * no file://, no php://filter, no data:// -- and leaves every internal HTTP
 * target wide open. A guard can be completely effective against one axis and
 * irrelevant on another.
 */
function route_scheme_only(): void
{
    $url = $_GET['url'] ?? '';
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        blocked("scheme $scheme is not allowed");
        return;
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-006

// @ssrefuse:begin php-007
/**
 * Resolves the hostname, rejects anything not public, then fetches by name.
 *
 * Two holes, and they are different in kind. The predicate is wrong: measured
 * on 8.4.27, filter_var with NO_PRIV_RANGE|NO_RES_RANGE calls 100.64.0.10 and
 * 100.100.100.200 public. And the fetch re-resolves the name, so even a
 * correct predicate would only describe the first of two lookups.
 */
function route_resolve_check(): void
{
    $url = $_GET['url'] ?? '';
    $host = (string) parse_url($url, PHP_URL_HOST);
    $ip = gethostbyname($host);
    if ($ip === $host) {
        sink_error("cannot resolve $host");
        return;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        blocked("$host resolves to non-public $ip");
        return;
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-007

// @ssrefuse:begin php-008
/**
 * Exact hostname allowlist, refused redirects, and http(s) only.
 *
 * The counterpart of the Python lab's py-012 and the JavaScript lab's js-013,
 * and labelled safe for the same reason: the name is compared exactly, the
 * redirect door is shut, and the scheme restriction closes the one remaining
 * door that curl in PHP opens wider than the other two runtimes -- its
 * protocol list includes dict, gopher, ldap, telnet and tftp, and a
 * gopher URL on the allowlisted host would still have satisfied a check that
 * only looked at the host.
 */
function route_allow_host_noredirect(): void
{
    $url = $_GET['url'] ?? '';
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host !== ALLOWED_HOST) {
        blocked("host $host is not the allowed host");
        return;
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_TIMEOUT, TIMEOUT);
    $body = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        sink_error($err !== '' ? $err : 'curl_exec returned false');
        return;
    }
    ok((string) $body);
}
// @ssrefuse:end php-008

// @ssrefuse:begin php-009
/**
 * Exact hostname allowlist, and the client follows redirects.
 *
 * The allowlist is correct about the first request and says nothing about the
 * second. PHP's http stream wrapper follows Location by default, so this route
 * does not have to opt in to the behaviour that breaks it -- which is the
 * reason it is written with file_get_contents rather than curl.
 */
function route_allow_host_redirect(): void
{
    $url = $_GET['url'] ?? '';
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    if ($host !== ALLOWED_HOST) {
        blocked("host $host is not the allowed host");
        return;
    }
    $body = @file_get_contents($url, false, http_ctx(true));
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-009

// @ssrefuse:begin php-010
/**
 * Allowlist written as a pattern that is not anchored at the end.
 *
 * The pattern is correct about how the authority starts and silent about where
 * it stops, so a longer name that begins the same way satisfies it.
 */
function route_allow_regex(): void
{
    $url = $_GET['url'] ?? '';
    if (preg_match('#^https?://public\.ssrefuse\.test#i', $url) !== 1) {
        blocked('url does not match the allowed pattern');
        return;
    }
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-010

// @ssrefuse:begin php-011
/**
 * URL assembled by interpolation, with only the authority tainted.
 *
 * Written to the same shape as the Python lab's assembled route so the two are
 * comparable: the scheme and the path are literals in the source and only the
 * host comes from the request, which is the flow a taint engine has to carry
 * through a concatenation rather than a single tainted argument.
 */
function route_assembled(): void
{
    $host = $_GET['host'] ?? '';
    $url = 'http://' . $host . '/feed.json';
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-011

// @ssrefuse:begin php-012
/**
 * Resolves, checks, then pins the connection to the address it checked.
 *
 * The pinning is right -- CURLOPT_RESOLVE closes the gap between the check and
 * the fetch, so rebinding has nothing to move. The predicate is still
 * filter_var's, and that is the hole: it calls CGNAT space public, so this
 * route pins faithfully to an address it should have rejected. A correct
 * mechanism with a wrong predicate fails, and it fails in a way that reads as
 * careful code.
 */
function route_resolve_pin(): void
{
    $url = $_GET['url'] ?? '';
    $host = (string) parse_url($url, PHP_URL_HOST);
    $port = (int) (parse_url($url, PHP_URL_PORT) ?: 80);
    $ip = gethostbyname($host);
    if ($ip === $host) {
        sink_error("cannot resolve $host");
        return;
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        blocked("$host resolves to non-public $ip");
        return;
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, TIMEOUT);
    curl_setopt($ch, CURLOPT_RESOLVE, ["$host:$port:$ip"]);
    $body = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        sink_error($err !== '' ? $err : 'curl_exec returned false');
        return;
    }
    ok((string) $body);
}
// @ssrefuse:end php-012

// @ssrefuse:begin php-013
/**
 * A correct allowlist check applied to the wrong copy of the value.
 *
 * Written to the same shape as the Python lab's py-021 so the pair is
 * comparable, and rewritten from a two-parameter version that could not be
 * probed at all: the first draft validated 'url' and fetched 'src', so a
 * request carrying only the payload failed the check on the empty one and the
 * route answered 403 to everything, including its own control. A variant that
 * cannot be reached is not a hard variant, it is an absent one.
 *
 * Decoding first looks like hardening and is what creates the gap: a
 * percent-encoded delimiter means the decoded copy and the raw copy have
 * different authorities, and the raw copy is the one fetched.
 */
function route_guard_wrong_value(): void
{
    $raw = $_GET['url'] ?? '';
    $candidate = rawurldecode($raw);
    $host = strtolower((string) parse_url($candidate, PHP_URL_HOST));
    if ($host !== ALLOWED_HOST) {
        blocked("host $host is not the allowed host");
        return;
    }
    $body = @file_get_contents($raw, false, http_ctx(false));
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-013

// @ssrefuse:begin php-014
/**
 * Resolve, reject every non-public range by hand, pin, and allow web ports only.
 *
 * The false-positive control for the resolve-and-pin shape. It differs from
 * php-012 in the predicate alone: the ranges are listed explicitly, including
 * the two filter_var was measured to miss, so there is no address left for the
 * target families to aim at.
 */
function route_resolve_pin_strict(): void
{
    $url = $_GET['url'] ?? '';
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        blocked("scheme $scheme is not allowed");
        return;
    }
    $host = (string) parse_url($url, PHP_URL_HOST);
    $port = (int) (parse_url($url, PHP_URL_PORT) ?: ($scheme === 'https' ? 443 : 80));
    if (!in_array($port, ALLOWED_PORTS, true)) {
        blocked("port $port is not allowed");
        return;
    }
    $ip = gethostbyname($host);
    if ($ip === $host || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        sink_error("cannot resolve $host to an IPv4 address");
        return;
    }
    foreach (PRIVATE_CIDRS as $cidr) {
        if (in_cidr($ip, $cidr)) {
            blocked("$host resolves into $cidr");
            return;
        }
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, TIMEOUT);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_RESOLVE, ["$host:$port:$ip"]);
    $body = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        sink_error($err !== '' ? $err : 'curl_exec returned false');
        return;
    }
    ok((string) $body);
}
// @ssrefuse:end php-014

// @ssrefuse:begin php-015
/**
 * A fetch with no attacker-controlled input anywhere in the URL.
 *
 * The false-positive control for the sink itself. Every sink-matching rule
 * fires on this line, and no input reaches it: the query parameter picks a
 * cache key, not a destination.
 */
function route_fixed_target(): void
{
    $label = preg_replace('/[^a-z0-9_-]/i', '', (string) ($_GET['label'] ?? 'default'));
    $url = ALLOWED_ORIGIN . '/feed.json';
    $body = @file_get_contents($url, false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    send(200, ['fetched' => true, 'label' => $label, 'body' => $body]);
}
// @ssrefuse:end php-015

// @ssrefuse:begin php-016
/**
 * The input selects from a fixed table of destinations instead of forming one.
 *
 * The allowlist the assignment asks about, done the way that actually holds:
 * the attacker chooses among URLs the application wrote, and never contributes
 * a character to the URL that is fetched.
 */
function route_indirect_choice(): void
{
    $feeds = [
        'news' => ALLOWED_ORIGIN . '/news.json',
        'images' => ALLOWED_ORIGIN . '/images.json',
        'status' => ALLOWED_ORIGIN . '/status.json',
    ];
    $key = (string) ($_GET['feed'] ?? '');
    if (!array_key_exists($key, $feeds)) {
        blocked('unknown feed');
        return;
    }
    $body = @file_get_contents($feeds[$key], false, http_ctx());
    if ($body === false) {
        sink_error('file_get_contents returned false');
        return;
    }
    ok($body);
}
// @ssrefuse:end php-016

$ROUTES = [
    '/preview/direct' => 'route_direct',
    '/preview/blind' => 'route_blind',
    '/preview/denylist-string' => 'route_denylist_string',
    '/preview/denylist-host' => 'route_denylist_host',
    '/preview/allow-prefix' => 'route_allow_prefix',
    '/preview/scheme-only' => 'route_scheme_only',
    '/preview/resolve-check' => 'route_resolve_check',
    '/preview/allow-host-noredirect' => 'route_allow_host_noredirect',
    '/preview/allow-host-redirect' => 'route_allow_host_redirect',
    '/preview/allow-regex' => 'route_allow_regex',
    '/preview/assembled' => 'route_assembled',
    '/preview/resolve-pin' => 'route_resolve_pin',
    '/preview/guard-wrong-value' => 'route_guard_wrong_value',
    '/preview/resolve-pin-strict' => 'route_resolve_pin_strict',
    '/preview/fixed-target' => 'route_fixed_target',
    '/preview/indirect-choice' => 'route_indirect_choice',
];

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === '/healthz') {
    send(200, ['ok' => true, 'lang' => 'php', 'php' => PHP_VERSION]);
    return;
}
if (isset($ROUTES[$path])) {
    ($ROUTES[$path])();
    return;
}
send(404, ['error' => 'no such route', 'routes' => array_keys($ROUTES)]);
