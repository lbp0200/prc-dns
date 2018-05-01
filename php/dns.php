<?php
if (count($_GET) === 0) {
    exit();
}
$root = 'https://dns.google.com/resolve?';
$parameters = [];
foreach ($_GET as $k => $v) {
    $parameters[] = "{$k}={$v}";
}
$url = $root . (implode('&', $parameters));
echo file_get_contents($url);