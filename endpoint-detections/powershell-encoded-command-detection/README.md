# PowerShell Encoded Command Detection

## Overview
This project detects suspicious execution of PowerShell commands that use Base64-encoded payloads.

Attackers frequently use the `-EncodedCommand` (`-enc`) parameter to obfuscate malicious PowerShell scripts and evade detection.

## Detection Objective
Detect PowerShell executions where the command line contains:
- `-EncodedCommand`
- `-enc`
- `FromBase64String`

## Why This Matters
Encoded PowerShell commands are commonly used to:
- Download malware
- Execute fileless attacks
- Establish persistence
- Bypass simple string-based detections

## Detection Logic
```text
processName = "powershell.exe"
AND (
    commandLine CONTAINS "-EncodedCommand"
    OR commandLine CONTAINS "-enc"
    OR commandLine CONTAINS "FromBase64String"
)
