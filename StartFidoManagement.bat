@echo off
cd /d "%~dp0"
"C:\Program Files\PowerShell\7\pwsh.exe" -ExecutionPolicy Bypass -File "%~dp0EnrollFIDO2_fido2-cred.ps1"