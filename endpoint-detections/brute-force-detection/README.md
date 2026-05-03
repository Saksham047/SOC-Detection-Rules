# Brute Force Detection

## Why this detection triggers
Multiple failed login attempts from the same IP address indicate a password guessing or credential stuffing attack.  
If these attempts are followed by a successful login, it strongly suggests that the attacker has successfully guessed the credentials and gained access.

---

## Sample Logs
See logs.txt for simulated attack scenario

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
## Sample Logs
See logs.txt for simulated attack scenario

```
# 🔐 ArcSight Detection – Suspicious Authentication Activity

---

## 📌 Overview

This project demonstrates detection of suspicious authentication behavior using **ArcSight Correlation Rules**.

The detection focuses on identifying:
- Brute force attempts (multiple failed logins)
- Possible account compromise (failed attempts followed by successful login)

---

## 🎯 Use Case

Detect when:
- A source performs multiple failed login attempts
- AND later successfully logs in using the same source

This pattern indicates a high likelihood of **credential compromise**.

---

## 📥 Log Source

- Windows Security Events:
  - **Event ID 4625** → Failed Login
  - **Event ID 4624** → Successful Login

---

## ⚙️ Detection Architecture

This detection is implemented using **two-stage correlation**:

---

### 🟡 Stage 1: Failed Login Detection

Condition:
- Event ID = 4625 (Failed Login)

Aggregation:
- Count ≥ 5
- Grouped by Attacker Address (Source IP)
- Within 2 minutes

Action:
- Add Source IP to Active List → `Suspicious_Auth_Activity`

---

### 🔴 Stage 2: Suspicious Successful Login

Condition:
- Authentication Success Event (4624)
- AND Source IP exists in Active List

Filter Conditions:
- Valid Source Address
- Valid Target Address
- loginAccount NOT IN ("Unknown user")
- Event Type IN (Base, Aggregated)

---

## 🌳 ArcSight Correlation Logic (Tree Format)

AND  
├── Category Behavior = /Authentication/Verify  
├── Category Outcome = /Success  
├── Attacker Address IS NOT NULL  
├── Target Address IS NOT NULL  
├── loginAccount NOT IN ("Unknown user")  
├── Type IN (Base, Aggregated)  
└── InActiveList("/All Lists/Suspicious_Auth_Activity")  

---

## 🧠 Detection Logic Explained

1. Multiple failed login attempts are tracked and stored in an Active List  
2. When a successful login occurs, the rule checks:
   - Was this source previously suspicious?  
3. If YES → Alert is triggered  

👉 This ensures detection of **real attack scenarios instead of isolated events**

---

## 🔥 Why Active Lists?

Active Lists provide:
- Stateful correlation (memory of past events)
- Reduced alert noise
- Better detection accuracy

Without Active Lists:
- Every failed login generates alerts ❌  

With Active Lists:
- Only meaningful attack patterns trigger alerts ✅  

---

## ⚖️ Filtering Strategy

``` id="flt2"
loginAccount NOT IN ("Unknown user")
