<?php
// Positive control for the PHP detectors. Scanned in the same invocation as
// the corpus, every time: a rule file that fails to load produces an empty
// result set, and a zero from a detector that does not work looks exactly
// like a zero from a clean codebase. Never scored.
function ssrefuse_control_fetch()
{
    $url = $_GET['target'] ?? '';
    return file_get_contents($url);
}

function ssrefuse_control_curl()
{
    $handle = curl_init($_GET['target'] ?? '');
    return curl_exec($handle);
}
