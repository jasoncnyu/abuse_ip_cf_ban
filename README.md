# IP Block Automation

This PHP script automates detection and blocking of suspicious IP addresses based on access logs. It leverages AbuseIPDB for IP reputation checking and Cloudflare for network-level blocking. Fallback blocking is also handled via a local denylist file.

---

## 🔧 Configuration

Edit the constants in the script header to fit your server setup:

```php
const ACCESS_LOG = '/path/to/access_log';
const CLOUD_FLARE_API_KEY = 'your_cloudflare_api_key';
const CLOUD_FLARE_EMAIL = 'your_email@example.com';
const CLOUDFLARE_ZONE_ID = 'your_cloudflare_zone_id';
const ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key';
const BAN_IP_LIST = '/path/to/blocked_ips.txt';

const KEYWORDS = ['wp-login.php', 'xmlrpc.php', 'admin', 'sqlmap'];
const TIME_WINDOW_SECONDS = 3600;       // Look back 1 hour
const ABUSE_SCORE_THRESHOLD = 80;       // Block if AbuseIPDB score is 80+
const LOG_LINE_COUNT = 10000;            // Tail last n lines
const REQUEST_THRESHOLD = 100;          // Block if over m requests
```

### ⚙️ Choosing Execution Interval

- You may run this script as often as you like (e.g. every 5 minutes, every hour).
- `TIME_WINDOW_SECONDS` should match your execution interval. For hourly runs, use 3600 seconds.
- Set `LOG_LINE_COUNT` large enough to ensure it covers more lines than the number generated within each time window (previous entries are ignored anyway).
- The appropriate interval depends on your server traffic and the frequency limits of Cloudflare and AbuseIPDB APIs.

---

## ✅ Features

- Parses recent log lines (`LOG_LINE_COUNT`)
- Filters entries within the recent time window (`TIME_WINDOW_SECONDS`)
- Flags IPs that:
  - Appear excessively (≥ `REQUEST_THRESHOLD`)
  - Contain suspicious keywords (`KEYWORDS`)
- Fetches abuse scores via AbuseIPDB
- Automatically blocks high-risk IPs using Cloudflare
- Falls back to local denylist if Cloudflare blocking fails
- Provides output messages even when no IPs are matched

---

## 💻 Usage

Run as a CLI script or via cron job:

```bash
php block_ips.php
```

Example cron for hourly execution:

```cron
0 * * * * /usr/bin/php /path/to/block_ips.php >> /var/log/ip_blocker.log 2>&1
```

---

## 🔐 Requirements

- PHP 7.4+
- curl extension enabled
- Cloudflare account and zone ID
- AbuseIPDB API key (free plan supported)

---

## 📁 Files

- `block_ips.php`: Main script
- `blocked_ips.txt`: Stores IPs fallback-blocked or repeated post-Cloudflare

---

## ⚠️ When Cloudflare Blocking Fails

If Cloudflare successfully blocks an IP, but that IP continues to appear in your access logs, it's likely that the traffic bypasses Cloudflare (e.g., direct server IP access).

In that case, consider:

1. Blocking at the firewall or network level (e.g., `iptables`, `ufw`, cloud VPC rules)
2. Blocking via the OS, web server, or PHP-level application deny rules

IPs that were already blocked by Cloudflare but reappear will be recorded in your `blocked_ips.txt` file. Use that file as a basis for additional blocking mechanisms.

---

## 🧪 Example Output

```bash
Checking: 203.0.113.1 (Count: 134) 
Blocking: 203.0.113.1 (Score: 90)
Result: {"success":true,"result":{...}}

Passed: 198.51.100.10 (Score: 40)
No suspicious IPs found within the last hour.
```
