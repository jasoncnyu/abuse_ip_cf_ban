<?php
const ACCESS_LOG = '/var/log/nginx/access.log'; // Update with actual log path
const CLOUDFLARE_API_KEY = 'YOUR_CLOUDFLARE_API_KEY';
const CLOUDFLARE_EMAIL = 'YOUR_EMAIL@example.com';
const CLOUDFLARE_ZONE_ID = 'YOUR_ZONE_ID';        // Use only one type of ID
const CLOUDFLARE_ACCOUNT_ID = 'YOUR_ACCOUNT_ID';  // If both are set, ACCOUNT_ID takes precedence
const CLOUDFLARE_NOTE = 'Auto-blocked by script';
const ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY';
const BAN_IP_LIST = '/home/web/ipban.txt';

// List of suspicious keywords to trigger IP counting
const KEYWORDS = ['wp-login.php', 'xmlrpc.php', 'admin', 'sqlmap'];

// Adjustable Parameters
const TIME_WINDOW_SECONDS = 3600;
const ABUSE_SCORE_THRESHOLD = 60;
const LOG_LINE_COUNT = 10000;
const REQUEST_THRESHOLD = 30;

// 1. Extract suspicious IPs from recent log lines based on request frequency and keywords
function get_suspicious_ips($logPath, $threshold = REQUEST_THRESHOLD): array {
    $cmd = "tail -n " . LOG_LINE_COUNT . " " . escapeshellarg($logPath) . " 2>&1";
    exec($cmd, $lines, $ret);

    if ($ret !== 0 || empty($lines)) {
        echo "❌ Failed to read log file: $logPath\n";
        echo "Command output:\n";
        foreach ($lines as $line) {
            echo "  $line\n";
        }
        return [];
    }

    $ipCounts = [];
    $keywordHits = [];
    $result = [];
    $timeLimit = time() - TIME_WINDOW_SECONDS;
    $recentLineFound = false;

    foreach ($lines as $line) {
    	//echo $line."<br>";
        if (preg_match('/^([\d\.]+) [^\[]+ \[([^\]]+)/', $line, $match)) {
            $ip = $match[1];
            $timeStr = $match[2];

            // Convert "02/Jun/2025:08:25:22 +0900" to "02 Jun 2025 08:25:22 +0900"
            $timeFormatted = preg_replace('/^(\d{2})\/(\w{3})\/(\d{4}):/', '$1 $2 $3 ', $timeStr);
            $timestamp = strtotime($timeFormatted);

            if ($timestamp === false || $timestamp < $timeLimit) {
                continue;
            }

            $recentLineFound = true;

            if (!isset($ipCounts[$ip])) $ipCounts[$ip] = 0;
            $ipCounts[$ip]++;

            foreach (KEYWORDS as $kw) {
                if (strpos($line, $kw) !== false) {
                    $keywordHits[$ip] = $line;
                    break;
                }
            }
        }
    }

    if (!$recentLineFound) {
        echo "No log entries within the past hour.\n";
        return [];
    }

    foreach ($ipCounts as $ip => $cnt) {
        if ($cnt >= $threshold) {
            $result[$ip] = $cnt;
        }
        else if(isset($keywordHits[$ip])) {
        	$result[$ip] = $keywordHits[$ip];
        }
    }

    if (empty($result)) {
        echo "No suspicious IPs found within the last hour.\n";
    }

    return $result;
}

// 2. Query abuse score from AbuseIPDB
function get_abuse_score($ip) {
    $ch = curl_init("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=30");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            "Key: " . ABUSEIPDB_API_KEY,
            "Accept: application/json"
        ]
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);

    $data = json_decode($resp, true);
    return $data['data']['abuseConfidenceScore'] ?? 0;
}

// 3. Block IP using Cloudflare API
function block_ip_cloudflare($ip) {
	$baseUrl = 'https://api.cloudflare.com/client/v4';
	$endpoint = defined('CLOUDFLARE_ACCOUNT_ID') && CLOUDFLARE_ACCOUNT_ID
	    ? "{$baseUrl}/accounts/" . CLOUDFLARE_ACCOUNT_ID . "/firewall/access_rules/rules"
	    : "{$baseUrl}/zones/" . CLOUDFLARE_ZONE_ID . "/firewall/access_rules/rules";

    $ch = curl_init($endpoint);
    $payload = json_encode([
        'mode' => 'block',
        'configuration' => [
            'target' => 'ip',
            'value' => $ip
        ],
        'notes' => CLOUDFLARE_NOTE
    ]);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            "X-Auth-Email: " . CLOUDFLARE_EMAIL,
            "X-Auth-Key: " . CLOUDFLARE_API_KEY,
            "Content-Type: application/json"
        ]
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return json_decode($result, true);
}

// 4. Append IP to PHP-level denylist file
function add_ip_to_php_denylist($ip, $filepath) {
    file_put_contents($filepath, $ip . "\n", FILE_APPEND | LOCK_EX);
}

// === Execution starts here ===
$ips = get_suspicious_ips(ACCESS_LOG);
echo "<pre>";
foreach ($ips as $ip => $cnt) {
    echo "Checking: $ip (Count: $cnt) ";
    $score = get_abuse_score($ip);
    if ($score >= ABUSE_SCORE_THRESHOLD) {
        echo "Blocking: $ip (Score: $score)\n";
        $res = block_ip_cloudflare($ip);
        echo "Result: " . json_encode($res) . "\n";

        // If Cloudflare failed to block, fallback to PHP denylist
        if (!$res['success']) {
            echo "Cloudflare block failed, fallback to PHP denylist\n";
            add_ip_to_php_denylist($ip, BAN_IP_LIST);
        }
    } else {
        echo "Passed: $ip (Score: $score)\n";
    }
}
echo "</pre>";
