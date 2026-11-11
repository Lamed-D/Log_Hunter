@echo off
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
py -3 -c "import sys" >nul 2>&1
if errorlevel 1 goto try_python
py -3 -m log_hunter.launcher run %*
exit /b %ERRORLEVEL%
:try_python
python -c "import sys" >nul 2>&1
if errorlevel 1 goto missing_python
python -m log_hunter.launcher run %*
exit /b %ERRORLEVEL%
:missing_python
echo Install Python 3.11 or newer with the Python launcher and Tcl/Tk.
powershell -NoProfile -NonInteractive -Command "$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ParentProcessId);$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ParentProcessId);if($p.Name -eq 'explorer.exe'){exit 0};exit 1" >nul 2>&1
if not errorlevel 1 pause
exit /b 1
