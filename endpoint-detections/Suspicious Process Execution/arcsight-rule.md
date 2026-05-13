# ArcSight Correlation Rule - Suspicious Process Execution

##  Rule Name
Suspicious Execution of LOLBins with Malicious Behavior

---

##  Purpose
Detect execution of commonly abused Windows binaries (LOLBins) with suspicious command-line arguments and user-driven parent processes, often indicative of phishing or initial access attacks.

---

##  Data Source
- Endpoint Process Events (Windows Logs / Sysmon / EDR Feed)

---

# ArcSight Correlation Rule: Suspicious Process Chain Detection

## Rule Name
Suspicious Process Chain Detection

## Objective
Detect potentially malicious parent-child process relationships that are commonly associated with malware execution, persistence, and command execution.

## Use Case
Attackers often abuse trusted Windows processes such as:
- cmd.exe
- powershell.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe

When these processes are launched by unusual parent processes (for example, Microsoft Word or Excel), it may indicate malicious activity.

## Detection Logic

Trigger an alert when:

### Parent Process
- winword.exe
- excel.exe
- outlook.exe
- powerpnt.exe
- chrome.exe
- firefox.exe
- teams.exe

### Child Process
- cmd.exe
- powershell.exe
- pwsh.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe

##  Correlation Condition

```text
deviceEventClassId = "Process Creation"
AND parentProcessName IN (
  "winword.exe",
  "excel.exe",
  "outlook.exe",
  "powerpnt.exe",
  "chrome.exe",
  "firefox.exe",
  "teams.exe"
)
AND processName IN (
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe"
)
## 📌 Notes

ArcSight correlation rules rely heavily on event matching conditions rather than query-based filtering like KQL. This rule is designed to replicate the same detection logic in enterprise SIEM format.
