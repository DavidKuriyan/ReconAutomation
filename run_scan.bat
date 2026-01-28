@echo off
cd "%~dp0orchestrator"
python orchestrator.py %*
if %errorlevel% neq 0 pause
