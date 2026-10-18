<?php
/* RAMP default document, written by the installer on first run. */
$phpinfo = isset($_GET['phpinfo']);
if ($phpinfo) {
    phpinfo();
    exit;
}
$checks = [
    'mysqli' => extension_loaded('mysqli'),
    'curl' => extension_loaded('curl'),
    'mbstring' => extension_loaded('mbstring'),
    'openssl' => extension_loaded('openssl'),
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RAMP Control Panel</title>
<style>
body { font: 15px/1.5 "Segoe UI", Arial, sans-serif; margin: 40px auto; max-width: 720px; color: #222; }
h1 { font-size: 26px; margin-bottom: 4px; }
.sub { color: #666; margin-bottom: 28px; }
table { border-collapse: collapse; width: 100%; margin: 18px 0; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #ddd; }
th { background: #f4f4f4; }
.ok { color: #157347; font-weight: 600; }
.ko { color: #b02a37; font-weight: 600; }
.links a { display: inline-block; margin-right: 14px; }
.note { color: #666; font-size: 13px; margin-top: 26px; }
</style>
</head>
<body>
<h1>RAMP</h1>
<div class="sub">Apache <?= htmlspecialchars(apache_get_version() ?: '?') ?> &middot; PHP <?= PHP_VERSION ?> &middot; <?= PHP_OS ?></div>
<table>
<tr><th>PHP extension</th><th>Status</th></tr>
<?php foreach ($checks as $ext => $on): ?>
<tr><td><?= $ext ?></td><td class="<?= $on ? 'ok' : 'ko' ?>"><?= $on ? 'loaded' : 'missing' ?></td></tr>
<?php endforeach; ?>
</table>
<div class="links">
<a href="/phpmyadmin/">phpMyAdmin</a>
<a href="?phpinfo=1">phpinfo()</a>
</div>
<div class="note">Replace this page (<?= htmlspecialchars(__FILE__) ?>) with your own project, or point Apache's DocumentRoot somewhere else.</div>
</body>
</html>
