@echo off
setlocal
chcp 65001 >nul
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 -X utf8 "%~dp0start.py"
goto finish
:use_python
where python >nul 2>nul
if errorlevel 1 goto missing_python
python -X utf8 "%~dp0start.py"
goto finish
:missing_python
echo Python 3.11+ is required. Install Python and run this file again.
pause
exit /b 2
:finish
set "patch_exit=%errorlevel%"
echo.
pause
exit /b %patch_exit%
