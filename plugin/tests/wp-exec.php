<?php

/*
 * Runs PHP code inside the test WordPress, the way a request would (shutdown hooks included).
 *   php wp-exec.php <site-dir> '<php code>'
 */

[$_, $site, $code] = $argv;
$_SERVER['HTTP_HOST'] = '127.0.0.1:8080';
$_SERVER['SERVER_NAME'] = '127.0.0.1';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['REQUEST_METHOD'] = 'GET';
require $site . '/wp-load.php';
eval($code);
