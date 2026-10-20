// Positive control for the JavaScript detectors.
//
// Scanned in the same invocation as the corpus, every time. A rule file that
// fails to load, a semgrep upgrade that changes pattern semantics, or a typo in
// a metavariable all produce an empty result set, and a zero from a detector
// that does not work looks exactly like a zero from a clean codebase. This file
// is the difference: it must produce at least one finding from every JavaScript
// configuration, and a run where it does not is reported as unusable.
//
// It is not part of the labelled corpus and is never scored.
'use strict';

const http = require('node:http');
const { execFile } = require('node:child_process');

// Inventory and taint both: request parameter straight into fetch.
async function controlFetch(req, res) {
  const target = req.query.target;
  const response = await fetch(target);
  res.json({ body: await response.text() });
}

// Inventory and taint: the low-level client, reached from a body field.
function controlHttpGet(req, res) {
  http.get(req.body.callback, (upstream) => upstream.pipe(res));
}

// Inventory only: the sink leaves the process.
function controlCurl(req) {
  execFile('curl', ['-s', req.query.target], () => {});
}

module.exports = { controlFetch, controlHttpGet, controlCurl };
