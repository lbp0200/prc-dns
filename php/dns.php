<?php
$is_https = false;
if (isset($_SERVER['HTTPS'])) {
    $is_https = true;
}
if (count($_GET) === 0) {
    exit();
}
$root = 'https://dns.google.com/resolve?';
$parameters = [];
foreach ($_GET as $k => $v) {
    $dv = $is_https ? $v : base64_decode(urldecode($v));
    $parameters[] = "{$k}={$dv}";
}
$url = $root . (implode('&', $parameters));

$resp = file_get_contents($url);
echo $is_https ? $resp : base64_encode($resp);