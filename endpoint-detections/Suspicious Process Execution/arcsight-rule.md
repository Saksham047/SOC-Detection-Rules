# ArcSight Correlation Rule - Suspicious Process Execution

## 🧠 Rule Name
Suspicious Execution of LOLBins with Malicious Behavior

---

## 🎯 Purpose
Detect execution of commonly abused Windows binaries (LOLBins) with suspicious command-line arguments and user-driven parent processes, often indicative of phishing or initial access attacks.

---

## 📥 Data Source
- Endpoint Process Events (Windows Logs / Sysmon / EDR Feed)

---

## ⚙️ Rule Logic (ArcSight ESM)

### 1. Base Filter (Target Processes)

IF Destination Process Name IN:

- mshta.exe
- regsvr32.exe
- wmic.exe
- bitsadmin.exe
- msbuild.exe
- installutil.exe

---

### 2. Command-Line Condition

AND Command Line CONTAINS ANY OF:

- http://
- https://
- javascript
- vbscript
- .dll
- .xml

---

### 3. Parent Process Condition

AND Initiating Process Name IN:

- winword.exe
- excel.exe
- outlook.exe
- wscript.exe
- cscript.exe

---

## 🚨 Correlation Rule Logic

Trigger Alert WHEN:

(Condition 1 AND Condition 2 AND Condition 3)

---

## 📊 Severity

| Condition Match | Severity |
|------|------|
| All 3 conditions | High |
| 2 conditions | Medium |
| 1 condition | Low / Ignore |

---

## 🧠 Use Case

- Phishing-based execution detection  
- Macro-based attack chains  
- Living-off-the-land binary abuse  
- Initial access detection

---

## ⚠️ False Positives

Possible benign activity:
- IT automation scripts
- Software deployment tools
- Admin maintenance tasks

---

## 🛡️ Mitigation Strategy

- Whitelist known admin/service accounts  
- Exclude trusted deployment servers  
- Validate parent process legitimacy  

---

## 🔥 Response Actions

- Investigate parent process origin  
- Check user email/download history  
- Analyze network connections  
- Isolate endpoint if confirmed malicious  

---

## 📌 Notes

ArcSight correlation rules rely heavily on event matching conditions rather than query-based filtering like KQL. This rule is designed to replicate the same detection logic in enterprise SIEM format.
