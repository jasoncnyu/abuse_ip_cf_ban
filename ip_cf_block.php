<?php
const ACCESS_LOG = '/var/log/nginx/access.log'; // Update with actual log path
const CLOUD_FLARE_API_KEY = 'YOUR_CLOUDFLARE_API_KEY';
const CLOUD_FLARE_EMAIL = 'YOUR_EMAIL@example.com';
const CLOUDFLARE_ZONE_ID = 'YOUR_ZONE_ID';
const ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY';
const BAN_IP_LIST = '/home/web/ipban.txt';

// List of suspicious keywords to trigger IP counting
const KEYWORDS = ['wp-login.php', 'xmlrpc.php', 'admin', 'sqlmap'];

// 1. Extract suspicious IPs from recent log lines based on request frequency and keywords
function get_suspicious_ips($logPath, $threshold = 10): array {
    exec("tail -n 1000 $logPath", $lines);
    $ipCounts = [];
    $keywordHits = [];

    foreach ($lines as $line) {
        if (preg_match('/^(\d+\.\d+\.\d+\.\d+)/', $line, $match)) {
            $ip = $match[1];
            if (!isset($ipCounts[$ip])) $ipCounts[$ip] = 0;
            $ipCounts[$ip]++;

            foreach (KEYWORDS as $kw) {
                if (strpos($line, $kw) !== false) {
                    $keywordHits[$ip] = true;
                    break;
                }
            }
        }
    }

    $result = [];
    foreach ($ipCounts as $ip => $cnt) {
        if ($cnt >= $threshold || isset($keywordHits[$ip])) {
            $result[$ip] = $cnt;
        }
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
    $ch = curl_init("https://api.cloudflare.com/client/v4/zones/" . CLOUDFLARE_ZONE_ID . "/firewall/access_rules/rules");
    $payload = json_encode([
        'mode' => 'block',
        'configuration' => [
            'target' => 'ip',
            'value' => $ip
        ],
        'notes' => 'Auto-blocked by script'
    ]);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            "X-Auth-Email: " . CLOUD_FLARE_EMAIL,
            "X-Auth-Key: " . CLOUD_FLARE_API_KEY,
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
foreach ($ips as $ip => $cnt) {
    echo "Checking: $ip (Count: $cnt)\n";
    $score = get_abuse_score($ip);
    if ($score >= 50) {
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
