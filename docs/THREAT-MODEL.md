# Threat model

STRIDE applied to the feature, not to the functions. The feature is: the application accepts a URL
from a request and fetches it server-side. Every lab variant exists because one of these questions
had an answer worth measuring.

### Spoofing

Can a request be made to look as if it came from the server rather than from the
caller? That is the whole point of SSRF: the internal admin service on `127.0.0.1:19001` has no
authentication because it trusts the network position of whoever connects, and the fetch feature
lends that position out. `py-001` through `py-005` are the plain forms.

### Tampering

Can state be changed between the check and the use? Two variants turn on this.
`py-013` resolves the hostname to validate it and resolves it again to connect, so the answer can
change in between; that is `B14_dns_rebinding`, and the DNS server returns alternating answers with
TTL 0 to make the window real. `py-019` and `py-020` split the write from the read: one request
stores a URL and another fetches it, so nothing tainted is visible in the function that sends the
request.

### Repudiation

Does the fetch leave a record tied to the caller? The blind variant `py-002`
discards the response, so from the caller's side there is nothing to show. The testbed answers this
from the other end: every target writes a JSONL access row, and the DNS server logs queries to the
out-of-band suffix, which is how a blind hit is confirmed at all.

### Information disclosure

What comes back. The fake metadata service returns credential-shaped
content, the internal admin service returns a role and a token, and `file://` on a urllib sink reads
a local file. Each target holds a distinct canary string, so the prober can tell which one a response
came from instead of inferring it from a status code.

### Denial of service

Out of scope here, and worth naming so the omission is explicit. A URL-fetch
feature can be pointed at a slow endpoint to exhaust worker threads, and the public stand-in host has
a `/slow` endpoint for that experiment. Nothing in the current corpus measures it.

### Elevation of privilege

Which value does this feature write that something else reads to make a
trust decision? For a preview feature the answer is usually none, and that is why the chain in this
corpus runs the other way: the feature reads the server's network position, which other services
treat as proof of authorization. The sink to trace is not a value the feature writes but the trust
the internal service places in the source address of a connection.

## What the allowlist assumes

Each guard in the corpus rests on an assumption, and the assumption is where the bug is.

- a substring or prefix check assumes the authority boundary is where the string ends
- an exact hostname check assumes the first request is the only request
- resolve-and-classify assumes the second lookup returns what the first one did
- decode-then-check assumes decoding does not move the authority
- "reject RFC 1918 and loopback" assumes those are the only non-public addresses

The bypass catalog is organised around those five assumptions rather than around payload syntax.
