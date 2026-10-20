/**
 * SSReFuse lab application (JavaScript / Node).
 *
 * The same link-preview feature as the Python lab, written the way a Node
 * service is written: one URL-fetching capability reached through many routes,
 * each with a different guard. Variants are bracketed by @ssrefuse:begin/end
 * markers so the corpus loader can attribute a finding without line numbers.
 *
 * The file is standalone -- no dependency beyond the Node standard library, and
 * no import from the ssrefuse package -- so static analysers see ordinary
 * application code. There is no npm install step: the router below has the
 * shape of an Express app because that is the shape detector rules are written
 * against, and writing it out is cheaper than taking 389 packages for it.
 *
 * Why this lab exists next to the Python one: the guard taxonomy is shared, so
 * the two labs differ only in the runtime, and the matrix difference is the
 * measurement. Three runtime facts drive most of that difference, each measured
 * rather than assumed (see docs/EVAL-PROTOCOL.md):
 *
 *   1. new URL() normalises 2130706433, 0177.0.0.1, 0x7f000001, 127.1 and
 *      percent-encoded authorities to 127.0.0.1, so a denylist over
 *      new URL(u).hostname catches spellings that defeat the same denylist in
 *      Python. The legacy url.parse() does not normalise, and the two sit side
 *      by side here as js-007 and js-008.
 *   2. fetch() refuses any URL carrying credentials, so userinfo confusion is
 *      not exploitable through that sink at all -- but http.get() accepts it
 *      and sends Basic auth. Same guard, different sink, different answer.
 *   3. fetch() follows redirects by default; http.get() never does.
 *
 * Testbed facts the guards are written against:
 *   public.ssrefuse.test   -> 192.88.99.10     the partner host this app trusts
 *   internal.ssrefuse.test -> 127.0.0.1        internal admin service, port 19001
 *   metadata.ssrefuse.test -> 169.254.169.254  fake cloud metadata
 */
'use strict';

const http = require('node:http');
const legacyUrl = require('node:url');
const dns = require('node:dns');
const net = require('node:net');
const { execFile } = require('node:child_process');

const ALLOWED_HOST = 'public.ssrefuse.test';
const ALLOWED_ORIGIN = 'http://public.ssrefuse.test';
const BLOCKED_SUBSTRINGS = ['127.0.0.1', 'localhost', '169.254.169.254'];
const BLOCKED_HOSTS = new Set(['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0']);
const TIMEOUT_MS = 4000;

// Pending preview jobs, written by one route and consumed by another. The
// second read is what makes the stored variant a second-order flow.
const PREVIEW_QUEUE = new Map();

// Address ranges that are not reachable from the public internet, written out
// because Node has no equivalent of Python's ipaddress module. The list matches
// what ipaddress.ip_address(x).is_global returns false for on the addresses
// this testbed uses, including 100.64.0.0/10, which is the range a guard
// phrased as "reject RFC 1918 and loopback" forgets.
const NON_GLOBAL_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function toInt(address) {
  return address.split('.').reduce((acc, part) => (acc * 256) + Number(part), 0);
}

function isGlobalAddress(address) {
  if (net.isIPv6(address)) {
    const low = address.toLowerCase();
    return !(low === '::1' || low === '::' || low.startsWith('fe80') || low.startsWith('fc')
             || low.startsWith('fd') || low.startsWith('::ffff:'));
  }
  if (!net.isIPv4(address)) return false;
  const value = toInt(address);
  return !NON_GLOBAL_V4.some(([network, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (value & mask) >>> 0 === (toInt(network) & mask) >>> 0;
  });
}

// ---------------------------------------------------------------------------
// A router with the shape of Express, and a response helper with the shape of
// one. Detector rules match on req.query / req.body / res.json, which is what
// they would match on in a real service.
// ---------------------------------------------------------------------------

function createApp() {
  const routes = [];

  function register(method, pattern, handler) {
    const keys = [];
    const source = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      .replace(/:([A-Za-z_]\w*)/g, (_match, name) => { keys.push(name); return '([^/]+)'; });
    routes.push({ method, pattern, handler, keys, regex: new RegExp(`^${source}$`) });
  }

  const app = {
    routes,
    get: (pattern, handler) => register('GET', pattern, handler),
    post: (pattern, handler) => register('POST', pattern, handler),
    listen,
  };

  function match(method, pathname) {
    for (const route of routes) {
      if (route.method !== method) continue;
      const found = route.regex.exec(pathname);
      if (!found) continue;
      const params = {};
      route.keys.forEach((key, index) => { params[key] = decodeURIComponent(found[index + 1]); });
      return { route, params };
    }
    return null;
  }

  async function readBody(request) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    if (chunks.length === 0) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      return {};
    }
  }

  function listen(port, onReady) {
    const server = http.createServer(async (request, response) => {
      // The incoming request is parsed once. A query value is decoded exactly
      // once here, so a payload that carries a percent-encoded delimiter
      // arrives at the handler in the form the attacker sent it.
      const incoming = new URL(request.url, 'http://127.0.0.1');
      const query = Object.fromEntries(incoming.searchParams.entries());
      const found = match(request.method, incoming.pathname);

      const res = {
        statusCode: 200,
        status(code) { this.statusCode = code; return this; },
        json(payload) {
          const text = JSON.stringify(payload);
          response.writeHead(this.statusCode, {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(text),
          });
          response.end(text);
        },
      };

      if (!found) {
        res.status(404).json({ ok: false, error: 'no such route' });
        return;
      }
      const req = {
        method: request.method,
        query,
        params: found.params,
        headers: request.headers,
        body: request.method === 'POST' ? await readBody(request) : {},
      };
      try {
        await found.route.handler(req, res);
      } catch (error) {
        // A sink that throws is a measurement, not a crash: it has to reach the
        // caller as a 5xx so the harness can tell "the client refused to send
        // this" apart from "the application refused this input".
        res.status(500).json({ ok: false, error: `${error.name}: ${error.message}` });
      }
    });
    server.listen(port, '127.0.0.1', () => onReady(server));
  }

  return app;
}

const app = createApp();

function ok(res, body, extra = {}) {
  return res.status(200).json({ ok: true, body: String(body).slice(0, 2000), ...extra });
}

function blocked(res, reason) {
  return res.status(403).json({ ok: false, blocked: reason });
}

// ---------------------------------------------------------------------------
// Every route calls its sink itself. Factoring the fetch into one helper would
// be the better code and the worse benchmark: a static finding would land on
// the helper for all twenty routes and could not be attributed to any of them.
// The one shared sink in this file is shared on purpose and labelled as such.
//
// readStream is not a sink. It consumes a response that has already arrived, so
// no request is made here and no rule should match it.
// ---------------------------------------------------------------------------

function readStream(response) {
  return new Promise((resolve) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => resolve({ status: response.statusCode, text }));
  });
}

// ---------------------------------------------------------------------------
// No guard at all
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-001
app.get('/preview/direct', async (req, res) => {
  // Textbook SSRF: the request parameter is the request target.
  const url = req.query.url || '';
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-001

// @ssrefuse:begin js-002
app.get('/preview/blind', async (req, res) => {
  // Same sink, but the response never reaches the caller. Only the fact that a
  // fetch happened is observable, so this variant can only be confirmed through
  // the target's own access log or a DNS callback.
  const url = req.query.url || '';
  try {
    await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch {
    // swallowed on purpose: the caller learns nothing either way
  }
  return res.status(200).json({ ok: true, queued: true });
});
// @ssrefuse:end js-002

// @ssrefuse:begin shared.fetchRemote
async function fetchRemote(target) {
  // Shared fetch helper: the hop that makes the flow interprocedural. This is
  // where a static finding for js-003 and js-004 lands, since the sink lives
  // here and not in either route. The region is marked shared so the evaluator
  // can attribute it to both callers instead of discarding it.
  const response = await fetch(target, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { status: response.status, text: await response.text() };
}
// @ssrefuse:end shared.fetchRemote

function unwrap(payload) {
  return (payload.source && payload.source.href) || '';
}

// @ssrefuse:begin js-003
app.get('/preview/helper', async (req, res) => {
  // Taint crosses a function boundary before reaching the sink.
  const url = req.query.url || '';
  const result = await fetchRemote(url);
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-003

// @ssrefuse:begin js-004
app.post('/preview/json', async (req, res) => {
  // Taint arrives nested inside a JSON body and is read back out of an object.
  const url = unwrap(req.body || {});
  const result = await fetchRemote(url);
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-004

// @ssrefuse:begin js-005
app.get('/preview/assembled', async (req, res) => {
  // Only the authority is attacker-controlled; the URL is built by the app.
  // Detectors that look for a tainted value reaching the sink whole tend to
  // miss this shape, because the string at the sink is a literal template.
  const host = req.query.host || ALLOWED_HOST;
  const path = req.query.path || '/status';
  const url = `http://${host}${path}`;
  const result = await new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: TIMEOUT_MS },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status, resolved: url });
});
// @ssrefuse:end js-005

// ---------------------------------------------------------------------------
// Denylists
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-006
app.get('/preview/denylist-string', async (req, res) => {
  // Rejects URLs whose raw text mentions a blocked address. The check never
  // parses the URL, so any alternative spelling of the same address walks
  // straight through -- and in Node the sink normalises several of those
  // spellings back to the address the denylist was written for.
  const url = req.query.url || '';
  for (const bad of BLOCKED_SUBSTRINGS) {
    if (url.toLowerCase().includes(bad)) {
      return blocked(res, `denylisted substring ${bad}`);
    }
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-006

// @ssrefuse:begin js-007
app.get('/preview/denylist-host-legacy', async (req, res) => {
  // Parses the URL with the legacy parser, then denylists the hostname. The
  // parser hands back the authority as written, so every alternative spelling
  // of an address is a different string here and none of them is on the list.
  const url = req.query.url || '';
  const host = String(legacyUrl.parse(url).hostname || '').toLowerCase();
  if (BLOCKED_HOSTS.has(host)) {
    return blocked(res, `denylisted host ${host}`);
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status, parsed_host: host });
});
// @ssrefuse:end js-007

// @ssrefuse:begin js-008
app.get('/preview/denylist-host', async (req, res) => {
  // The same denylist over the same URL, parsed with the WHATWG parser. That
  // parser canonicalises the authority before the comparison, so the numeric
  // spellings collapse onto an entry that is on the list. It is still a
  // denylist: it only knows the names someone thought to write down.
  const url = req.query.url || '';
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (BLOCKED_HOSTS.has(host)) {
    return blocked(res, `denylisted host ${host}`);
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status, parsed_host: host });
});
// @ssrefuse:end js-008

// ---------------------------------------------------------------------------
// Allowlists that operate on the URL as text
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-009
app.get('/preview/allow-prefix', async (req, res) => {
  // Allowlist by string prefix: the authority boundary is not where the prefix
  // ends, so the trusted name can be extended or demoted to userinfo. This
  // variant fetches with http.get, which accepts credentials in the URL.
  const url = req.query.url || '';
  if (!url.startsWith(ALLOWED_ORIGIN)) {
    return blocked(res, 'origin not allowlisted');
  }
  const result = await new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: TIMEOUT_MS },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-009

// @ssrefuse:begin js-010
app.get('/preview/allow-substring', async (req, res) => {
  // Allowlist by substring: the trusted name can appear anywhere, including in
  // a path, a query parameter or a fragment of someone else's URL. The sink is
  // fetch, which refuses a URL carrying credentials, so the userinfo trick that
  // defeats the prefix check above cannot be used through this one.
  const url = req.query.url || '';
  if (!url.includes(ALLOWED_HOST)) {
    return blocked(res, 'allowlisted host not present in url');
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-010

// @ssrefuse:begin js-011
app.get('/preview/allow-regex', async (req, res) => {
  // Allowlist by regex with no end anchor.
  const url = req.query.url || '';
  if (!new RegExp(`^https?://${ALLOWED_HOST.replace(/\./g, '\\.')}`).test(url)) {
    return blocked(res, 'url does not match allowlist pattern');
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-011

// ---------------------------------------------------------------------------
// Allowlists that parse the URL properly
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-012
app.get('/preview/allow-host-redirects', async (req, res) => {
  // Exact hostname allowlist on the URL the app was given. fetch follows
  // redirects unless told not to, so the guard describes the first request and
  // the client then goes wherever that host points it.
  const url = req.query.url || '';
  let host;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (host !== ALLOWED_HOST) {
    return blocked(res, 'host not allowlisted');
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status, final_url: result.finalUrl });
});
// @ssrefuse:end js-012

// @ssrefuse:begin js-013
app.get('/preview/allow-host-noredirect', async (req, res) => {
  // Exact hostname allowlist, redirects refused.
  const url = req.query.url || '';
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return blocked(res, 'scheme not allowed');
  }
  if (parsed.hostname.toLowerCase() !== ALLOWED_HOST) {
    return blocked(res, 'host not allowlisted');
  }
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text() };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-013

// @ssrefuse:begin js-014
app.get('/preview/resolve-check', async (req, res) => {
  // Resolves the hostname, rejects non-public addresses, then fetches by name.
  // The address that was validated and the address that is connected to come
  // from two separate lookups.
  const url = req.query.url || '';
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return blocked(res, 'scheme not allowed');
  }
  let address;
  try {
    address = (await dns.promises.lookup(parsed.hostname)).address;
  } catch {
    return blocked(res, 'host does not resolve');
  }
  if (!isGlobalAddress(address)) {
    return blocked(res, `non-public address ${address}`);
  }
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text() };
  return ok(res, result.text, { status: result.status, validated_address: address });
});
// @ssrefuse:end js-014

// @ssrefuse:begin js-015
app.get('/preview/resolve-pin', async (req, res) => {
  // Resolves once, validates the address, and connects to that same address by
  // handing the socket a lookup function that can only answer with it. The
  // hostname still travels in the Host header, and http.get does not follow
  // redirects, so there is no second lookup to win and no redirect to chase.
  const url = req.query.url || '';
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return blocked(res, 'scheme not allowed');
  }
  let address;
  try {
    address = (await dns.promises.lookup(parsed.hostname)).address;
  } catch {
    return blocked(res, 'host does not resolve');
  }
  if (!isGlobalAddress(address)) {
    return blocked(res, `non-public address ${address}`);
  }
  const pinned = (_hostname, options, callback) => {
    const done = typeof options === 'function' ? options : callback;
    done(null, address, net.isIPv6(address) ? 6 : 4);
  };
  const result = await new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: TIMEOUT_MS, lookup: pinned },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status, connected_to: address });
});
// @ssrefuse:end js-015

// @ssrefuse:begin js-016
app.get('/preview/scheme-only', async (req, res) => {
  // Checks the scheme and nothing else.
  const url = req.query.url || '';
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return blocked(res, 'scheme not allowed');
  }
  const response = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-016

// ---------------------------------------------------------------------------
// Sink diversity
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-017
app.get('/preview/httpget', async (req, res) => {
  // The low-level client with no guard. It accepts a URL carrying credentials
  // and turns it into a Basic auth header, which is why the userinfo family
  // reaches an internal target through this sink and not through fetch.
  const url = req.query.url || '';
  const result = await new Promise((resolve, reject) => {
    const request = http.get(url, { timeout: TIMEOUT_MS },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-017

// @ssrefuse:begin js-018
app.get('/preview/curl', async (req, res) => {
  // The fetch is delegated to the curl binary, so the sink leaves the process
  // entirely and library-level rules see nothing.
  const url = req.query.url || '';
  const text = await new Promise((resolve) => {
    execFile('curl', ['-s', '--max-time', String(TIMEOUT_MS / 1000), url],
      { timeout: TIMEOUT_MS + 2000 }, (_error, stdout) => resolve(stdout || ''));
  });
  return ok(res, text);
});
// @ssrefuse:end js-018

// ---------------------------------------------------------------------------
// Flows that defeat single-pass reasoning
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-019
app.post('/preview/enqueue', async (req, res) => {
  // Stores the URL. No fetch happens here, so this route is not the sink.
  const jobId = String(PREVIEW_QUEUE.size + 1);
  PREVIEW_QUEUE.set(jobId, { url: (req.body || {}).url || '', state: 'pending' });
  return res.status(200).json({ ok: true, job_id: jobId });
});
// @ssrefuse:end js-019

// @ssrefuse:begin js-020
app.get('/preview/run/:jobId', async (req, res) => {
  // Fetches a URL stored by an earlier request: a second-order flow. Nothing
  // tainted appears in this function; the taint was persisted by js-019 and is
  // read back out of module state here.
  const job = PREVIEW_QUEUE.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ ok: false, error: 'no such job' });
  }
  const response = await fetch(job.url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text(), finalUrl: response.url };
  job.state = 'done';
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-020

// @ssrefuse:begin js-021
app.get('/preview/checked-wrong-value', async (req, res) => {
  // A correct allowlist check applied to the wrong variable. `candidate` is
  // validated; `raw` is fetched. Decoding first looks like hardening, and it is
  // what creates the gap: a percent-encoded delimiter means the decoded copy
  // and the raw copy have different authorities. Half-correct code like this is
  // the ordinary shape of the bug in real applications, and it is why a
  // detector must bind a guard to the value that reaches the sink rather than
  // to whatever check appears nearby.
  const raw = req.query.url || '';
  const candidate = decodeURIComponent(raw);
  let host;
  try {
    host = new URL(candidate).hostname.toLowerCase();
  } catch {
    return blocked(res, 'unparsable url');
  }
  if (host !== ALLOWED_HOST) {
    return blocked(res, 'host not allowlisted');
  }
  const result = await new Promise((resolve, reject) => {
    const request = http.get(raw, { timeout: TIMEOUT_MS },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-021

// ---------------------------------------------------------------------------
// Routes that must never be reported: the false-positive controls
// ---------------------------------------------------------------------------

// @ssrefuse:begin js-022
app.get('/status/upstream', async (req, res) => {
  // Fetches a fixed URL. No user input is involved anywhere in this route.
  const response = await fetch(`${ALLOWED_ORIGIN}/health`, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  const result = { status: response.status, text: await response.text() };
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-022

// @ssrefuse:begin js-023
app.get('/preview/path-only', async (req, res) => {
  // User input reaches the URL, but only the path, and the authority is fixed.
  // The validation rejects every character that could end the path component
  // and take over the authority.
  const path = req.query.path || '/status';
  if (!path.startsWith('/') || /[@?#\\]/.test(path) || path.includes('//')) {
    return blocked(res, 'invalid path');
  }
  const result = await new Promise((resolve, reject) => {
    const request = http.get(`${ALLOWED_ORIGIN}${path}`, { timeout: TIMEOUT_MS },
      (response) => resolve(readStream(response)));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.on('error', reject);
  });
  return ok(res, result.text, { status: result.status });
});
// @ssrefuse:end js-023

app.get('/', async (req, res) => {
  const routes = app.routes.map((route) => `${route.method} ${route.pattern}`).sort();
  return res.status(200).json({ app: 'ssrefuse-node-lab', routes });
});

const port = Number(process.argv[2] || 19081);
app.listen(port, () => {
  // Printed so the harness can confirm which build is answering, read out of
  // the running process rather than off disk.
  process.stdout.write(
    `LAB-READY name=node_ssrf port=${port} routes=${app.routes.length - 1}\n`);
});
