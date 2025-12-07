@echo off
TITLE My Windows Real-time Network Connection Monitor

:: Request Administrator Privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting Administrator Privileges...
    goto UACPrompt
) else (
    goto gotAdmin
)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%~dp0"

echo =====================================================
echo My Windows Real-time Network Connection Monitor (Administrator Mode)
echo =====================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found
    pause
    exit
)

:: Start application
echo Starting My Windows Real-time Network Connection Monitor with administrator privileges...
echo Please visit http://localhost:8080 to view monitoring interface
echo.

python start_web_interface.py

echo.
echo Application stopped
pause