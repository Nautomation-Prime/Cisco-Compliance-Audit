@echo off
setlocal

REM ------------------------------------------------------------------------------
REM Cisco Compliance Audit - First-Time Setup
REM # SPDX-License-Identifier: GPL-3.0-only
REM # Copyright (c) 2026 Christopher Davies
REM
REM Downloads a self-contained Python embeddable runtime and installs all
REM required packages into it. Runs automatically from run.bat when
REM python_runtime\ is missing. Requires an internet connection (one-time only).
REM
REM NOTE: PyATS/Genie are Linux/macOS only and are skipped on Windows (platform
REM       marker in requirements.txt). TextFSM (ntc-templates) is used instead.
REM
REM To upgrade Python: update PY_VER and PY_SHORT below, delete python_runtime\,
REM then run this script again.
REM ------------------------------------------------------------------------------

set "ROOT=%~dp0"
set "RUNTIME=%ROOT%python_runtime"
set "PY_VER=3.12.9"
set "PY_SHORT=312"
set "PY_ZIP=python-%PY_VER%-embed-amd64.zip"
set "PY_URL=https://www.python.org/ftp/python/%PY_VER%/%PY_ZIP%"
set "PIP_URL=https://bootstrap.pypa.io/get-pip.py"

echo.
echo ================================================================================
echo  Cisco Compliance Audit - First-Time Setup
echo ================================================================================
echo.
echo  Python %PY_VER% (embeddable) and all required packages will be downloaded.
echo  An internet connection is required. This only runs once.
echo.
echo  NOTE: PyATS/Genie are Linux/macOS only and will NOT be installed on Windows.
echo        TextFSM (ntc-templates) will be used for structured parsing instead.
echo.
echo  Press any key to begin, or Ctrl+C to cancel.
echo.
pause >nul

if not exist "%RUNTIME%" mkdir "%RUNTIME%"

echo.
echo [1/5] Downloading Python %PY_VER% embeddable package...
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%RUNTIME%\%PY_ZIP%' -UseBasicParsing -ErrorAction Stop"
if errorlevel 1 goto :error

echo [2/5] Extracting Python runtime...
powershell -NoProfile -Command "Expand-Archive -Path '%RUNTIME%\%PY_ZIP%' -DestinationPath '%RUNTIME%' -Force -ErrorAction Stop"
if errorlevel 1 goto :error
del "%RUNTIME%\%PY_ZIP%"

echo [3/5] Configuring embedded Python search paths...
powershell -NoProfile -Command ^
  "$pth = Join-Path '%RUNTIME%' ('python%PY_SHORT%._pth');" ^
  "$lines = Get-Content $pth;" ^
  "$lines = $lines | ForEach-Object { if ($_ -match '^\s*#\s*import site\s*$') { 'import site' } else { $_ } };" ^
  "if (-not ($lines -contains '..')) { $lines = @('..') + $lines };" ^
  "Set-Content -Path $pth -Value $lines -Encoding ASCII"
if errorlevel 1 goto :error

echo [4/5] Installing pip...
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%PIP_URL%' -OutFile '%RUNTIME%\get-pip.py' -UseBasicParsing -ErrorAction Stop"
if errorlevel 1 goto :error
"%RUNTIME%\python.exe" "%RUNTIME%\get-pip.py" --no-warn-script-location
if errorlevel 1 goto :error
del "%RUNTIME%\get-pip.py"

echo [5/5] Installing dependencies (this may take several minutes)...
"%RUNTIME%\python.exe" -m pip install -r "%ROOT%requirements.txt" --no-warn-script-location
if errorlevel 1 goto :error

REM pywin32 is required by keyring on Windows; the post-install step registers its DLLs
"%RUNTIME%\python.exe" "%RUNTIME%\Scripts\pywin32_postinstall.py" -install >nul 2>&1

echo.
echo ================================================================================
echo  Setup complete.  Run run.bat to launch the tool.
echo ================================================================================
echo.
endlocal
exit /b 0

:error
echo.
echo ================================================================================
echo  [FAILED] Setup did not complete. Resolve the error above and try again.
echo  If the download failed, check your internet connection.
echo  To retry: delete python_runtime\ and run this script again.
echo ================================================================================
echo.
pause
endlocal
exit /b 1
