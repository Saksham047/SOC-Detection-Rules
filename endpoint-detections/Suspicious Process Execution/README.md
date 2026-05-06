# Suspicious Process Execution Detection

## 🧠 Overview
This rule detects suspicious execution of commonly abused Windows native binaries (LOLBins) combined with malicious command-line activity and user-driven parent processes. These patterns are often associated with phishing-based initial access and script-based attacks.

---

## 🎯 Detection Logic

The rule triggers when:

- A known suspicious process is executed
- The command line shows signs of malicious behavior (web/script/payload activity)
- The process is initiated by user-driven applications like Office or scripting engines

---

## 🚨 Suspicious Processes Monitored

- mshta.exe
- regsvr32.exe
- wmic.exe
- bitsadmin.exe
- msbuild.exe
- installutil.exe

---

## ⚠️ Suspicious Behaviors

- Web-based execution (http/https)
- Script execution (javascript/vbscript)
- File payload indicators (.dll, .xml)
- Download activity patterns

---

## 👨‍💻 Parent Process Context

High-risk if initiated by:

- winword.exe
- excel.exe
- outlook.exe
- wscript.exe
- cscript.exe

---

## 📊 Sample Logs

See `sample-logs.txt` for simulated attack scenarios including:
- Phishing-based execution chains
- Script-based payload downloads
- Office-driven process spawning

---

## 🔥 MITRE ATT&CK Mapping

- T1059 - Command and Scripting Interpreter  
- T1204 - User Execution  
- T1218 - Signed Binary Proxy Execution  

---

## ⚠️ False Positives & Tuning

Possible false positives:
- IT automation scripts
- Admin deployment tools
- Internal system update processes

Mitigation:
- Whitelist trusted service accounts
- Exclude known automation servers
- Apply path-based exclusions for trusted directories

---

## 🛡️ Response Actions

- Investigate parent process origin
- Validate user activity legitimacy
- Check network connections from endpoint
- Review recent email/download activity

---

## 📌 Author Notes

This rule is designed for SOC-level detection engineering practice and focuses on balancing detection accuracy with noise reduction.
