# ArcSight Correlation Rule – Brute Force Detection

---

## 🧾 Rule Name
Brute Force Login Attempt Detection

---

## 🎯 Use Case
Detect brute force attempts using multiple failed logins (Event ID 4625), and identify possible compromise when followed by a successful login (Event ID 4624).

---

## 📥 Log Source

- Windows Security Events  
  - **Event ID 4625** → Failed Login  
  - **Event ID 4624** → Successful Login  

---

## ⚙️ ArcSight Rule Configuration

### 📌 Rule Type
Threshold-Based Correlation Rule

---

### 📌 Event Selection (Filter Conditions)
-deviceEventClassId = "4625"

---

### 📌 Grouping (Aggregation)
Group By:
Source Address (src)


---

### 📌 Threshold Condition
Trigger when:
COUNT(deviceEventClassId = 4625) > 5
WITHIN 5 minutes
BY same Source Address


---
## 🚨 Alert Details

- Severity:
  - Medium → Multiple failed attempts  
  - High → Failed + Successful login correlation  

- Category: Authentication Attack  
- MITRE ATT&CK: T1110 – Brute Force  

---

## ⚠️ False Positives

- User entering incorrect password multiple times  
- Expired credentials  
- VPN / IP switching  
- Automated scripts or health checks  

---

## 🛠️ Recommended Response

- Block source IP (if external)  
- Lock user account  
- Force password reset  
- Notify SOC team  
- Investigate for lateral movement  

---

## 📌 Notes

- Threshold values (8 attempts / 2 min) can be tuned  
- Baseline behavior should be considered before deployment  
- Can be implemented using ArcSight ESM with aggregation and event chaining  
