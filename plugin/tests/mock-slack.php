<?php

/*
 * Stand-in for a Slack Incoming Webhook (php -S router script).
 * Appends every received message to the file in $MOCK_SLACK_LOG, one JSON per line.
 * Returns 500 while the file $MOCK_SLACK_LOG.down exists, to simulate an outage.
 */

$log = getenv('MOCK_SLACK_LOG');
if (is_file($log . '.down')) {
    http_response_code(500);
    echo 'down';
    return true;
}
$body = file_get_contents('php://input');
$json = json_decode($body, true);
file_put_contents($log, json_encode(['text' => $json['text'] ?? null], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
echo 'ok';
return true;
