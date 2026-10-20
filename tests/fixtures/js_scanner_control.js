// Control input for the JavaScript scanner. Every construct below is one the
// scanner has to get right, and the expected result is written down in
// tests/test_slicing_js.py rather than derived from the scanner itself: a
// wrong statement count looks exactly like a right one.
//
// This file is never scanned by a detector and is never part of the corpus.
/**
 * A JSDoc block, which is what this project counts as a docstring in
 * JavaScript. It mentions a slash // and a brace { and a quote ' on purpose,
 * because a scanner that leaves comment mode early would act on them.
 */
'use strict';

const NOT_A_COMMENT = 'http://example.test//path?a={b}';
const TEMPLATE = `prefix ${NOT_A_COMMENT} { literal brace } suffix`;
const PATTERN = /[/{}()[\]]+/g;
const RATIO = 10 / 2 / 1;

function controlFunction(value) {
  const inner = `${value}/${RATIO}`;
  return inner.replace(/[{}]/g, '');
}

module.exports = { controlFunction, PATTERN, TEMPLATE, NOT_A_COMMENT };
