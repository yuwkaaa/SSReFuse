/*
 * Static-only corpus: JavaScript HTTP clients that need a package tree.
 *
 * The Node lab uses the standard library and installs nothing, so axios, got,
 * superagent and express never appear in code that runs. They are the clients
 * real services use, and a rule that only matches fetch and http.get would
 * look better than it is.
 *
 * The reason is a dependency tree, not a missing tool: a lab whose results
 * depend on a few hundred third-party packages is a lab whose results are
 * partly about those packages. (An earlier version of this comment said npm
 * was unavailable on the build machine. It is installed, in a self-contained
 * prefix rather than on PATH, which is a different statement -- and the
 * stronger reason stands on its own.)
 *
 * Nothing here runs. These functions exist so the sink-inventory rules are
 * measured against the shapes they will meet outside this repository, and
 * every sink carries an @ssrefuse:sink marker so a miss is counted.
 */
'use strict';

const axios = require('axios');
const got = require('got');
const superagent = require('superagent');
const express = require('express');

const app = express();
const ALLOWED_HOST = 'public.ssrefuse.test';

app.get('/preview/axios', async (req, res) => {
  const url = req.query.url;
  // @ssrefuse:sink js-axios-get
  const response = await axios.get(url);
  res.json({ body: response.data });
});

app.get('/preview/axios-callable', async (req, res) => {
  // @ssrefuse:sink js-axios-callable
  const response = await axios(req.query.url);
  res.json({ body: response.data });
});

app.post('/preview/got', async (req, res) => {
  const url = req.body.target;
  // @ssrefuse:sink js-got
  const response = await got(url);
  res.json({ body: response.body });
});

app.get('/preview/superagent', async (req, res) => {
  // @ssrefuse:sink js-superagent
  const response = await superagent.get(req.query.url);
  res.json({ body: response.text });
});

app.get('/preview/allowlisted', async (req, res) => {
  const url = req.query.url;
  if (new URL(url).hostname.toLowerCase() !== ALLOWED_HOST) {
    res.status(403).json({ blocked: 'host not allowlisted' });
    return;
  }
  // @ssrefuse:sink js-axios-guarded
  const response = await axios.get(url);
  res.json({ body: response.data });
});

module.exports = app;
