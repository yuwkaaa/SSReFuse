<?php
/**
 * Static-only corpus: PHP.
 *
 * Nothing here runs in the testbed. There is no PHP lab yet, so these routes
 * have no dynamic ground truth and they must never enter the precision and
 * recall table: a label nobody reproduced is a claim about a file, and this
 * project scores detectors against labels the prober confirmed.
 *
 * What they are for is the other half of the question -- "which sinks does a
 * rule see" -- which does not need the code to run. Every outbound-request
 * sink is marked with @ssrefuse:sink so the evaluator can say how many of the
 * sinks that are there were found, and name the ones that were not.
 *
 * The shapes are the ordinary ones: a URL from the query string reaching a
 * fetch, with the guards a PHP codebase actually writes.
 */

const ALLOWED_HOST = 'public.ssrefuse.test';

function preview_direct(): string
{
    $url = $_GET['url'] ?? '';
    // @ssrefuse:sink php-file-get-contents
    return (string) file_get_contents($url);
}

function preview_curl(): string
{
    $url = $_GET['url'] ?? '';
    $handle = curl_init($url);
    curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
    // @ssrefuse:sink php-curl-exec
    $body = curl_exec($handle);
    curl_close($handle);
    return (string) $body;
}

function preview_fopen(): string
{
    $url = $_POST['target'] ?? '';
    // @ssrefuse:sink php-fopen
    $stream = fopen($url, 'rb');
    $body = $stream ? stream_get_contents($stream) : '';
    if ($stream) {
        fclose($stream);
    }
    return $body;
}

function preview_headers(): array
{
    $url = $_GET['url'] ?? '';
    // @ssrefuse:sink php-get-headers
    return (array) get_headers($url);
}

function preview_xml(): ?SimpleXMLElement
{
    $url = $_REQUEST['feed'] ?? '';
    // @ssrefuse:sink php-simplexml-load-file
    return simplexml_load_file($url) ?: null;
}

function preview_socket(string $host, int $port): string
{
    // @ssrefuse:sink php-fsockopen
    $socket = fsockopen($host, $port, $errno, $errstr, 4);
    if (!$socket) {
        return '';
    }
    fwrite($socket, "GET / HTTP/1.0\r\n\r\n");
    $body = stream_get_contents($socket);
    fclose($socket);
    return $body;
}

function mirror_to_disk(): bool
{
    $url = $_GET['url'] ?? '';
    // @ssrefuse:sink php-copy
    return copy($url, '/tmp/ssrefuse-mirror');
}

/**
 * The guard a PHP codebase reaches for first, and the one with published
 * bypasses: FILTER_VALIDATE_URL checks that a string looks like a URL, which
 * is not the same question as "where will this connect". Forms such as
 * `0://evil.example;good.example` have been accepted by it. Kept here as a
 * guard shape for the rules to meet, not as a claim about any PHP version --
 * there is no PHP lab in this project, so nothing here is confirmed by a
 * request, and the sink below is marked only so the inventory can count it.
 */
function preview_filter_var(): string
{
    $url = $_GET['url'] ?? '';
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return '';
    }
    // @ssrefuse:sink php-file-get-contents-filtervar
    return (string) file_get_contents($url);
}

/**
 * A hostname allowlist applied after parsing, which is the correct shape and
 * the wrong effect: parse_url returns the authority as written, so an
 * alternative spelling of the same address is a different string here. This
 * function is the false-positive counterpart for the PHP rules -- a detector
 * that reports it has to say what it thinks is wrong with it.
 */
function preview_allowlisted(): string
{
    $url = $_GET['url'] ?? '';
    $host = parse_url($url, PHP_URL_HOST);
    if (strtolower((string) $host) !== ALLOWED_HOST) {
        return '';
    }
    // @ssrefuse:sink php-file-get-contents-guarded
    return (string) file_get_contents($url);
}
