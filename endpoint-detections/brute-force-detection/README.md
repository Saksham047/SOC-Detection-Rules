# Brute Force Detection

## Why this detection triggers
Multiple failed login attempts from the same IP address indicate a password guessing or credential stuffing attack.  
If these attempts are followed by a successful login, it strongly suggests that the attacker has successfully guessed the credentials and gained access.

---

## How this detection triggers

### Microsoft Sentinel (KQL)
```kql
let timeframe = 2m;
let threshold = 5;

let failed = SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IPAddress, bin(TimeGenerated, timeframe)
| where FailedAttempts >= threshold;

let success = SecurityEvent
| where EventID == 4624
| project Account, IPAddress, TimeGenerated;

failed
| join kind=inner success on Account, IPAddress
| where success_TimeGenerated > TimeGenerated
