@echo off
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
py -3 -c "import sys" >nul 2>&1
if errorlevel 1 goto try_python
py -3 -m log_hunter.launcher live %*
exit /b %ERRORLEVEL%
:try_python
python -c "import sys" >nul 2>&1
if errorlevel 1 goto missing_python
python -m log_hunter.launcher live %*
exit /b %ERRORLEVEL%
:missing_python
call "%~dp0run.bat" --help
exit /b 1
