@echo off
setlocal EnableExtensions

REM ------------------------------------------------------------------------------
REM Cisco Compliance Audit - Portable Launcher
REM # SPDX-License-Identifier: GPL-3.0-only
REM # Copyright (c) 2026 Christopher Davies
REM ------------------------------------------------------------------------------

REM === Relaunch maximised (one-time) ============================================
REM If we're not already in the re-launched window, start a maximised cmd that
REM calls this exact batch file again, then exit the current instance.
if not defined COMPLIANCE_STARTED (
    set "COMPLIANCE_STARTED=1"
    start "" /max "%ComSpec%" /c ""%~f0" %*"
    exit /b
)

REM === Normal execution continues here (in the maximised window) ================
set "ROOT=%~dp0"
set "PYTHON=%ROOT%python_runtime\python.exe"
set "PACKAGE_DIR=%ROOT%compliance_audit"

cls
echo.
echo ================================================================================
echo                   CISCO COMPLIANCE AUDIT TOOL
echo ================================================================================
echo.
echo  Starting pre-flight checks...
echo.

REM Bootstrap runtime on first run
if not exist "%PYTHON%" (
    echo  Python runtime not found - running first-time setup...
    echo.
    call "%ROOT%setup.bat"
    if errorlevel 1 (
        echo.
        echo  [FAILED] Setup did not complete. Cannot continue.
        pause
        endlocal
        exit /b 1
    )
    echo.
)

REM Check package is present
if not exist "%PACKAGE_DIR%\__init__.py" (
    echo  [ERROR] Package not found at: %PACKAGE_DIR%
    goto :error
)

REM Check compliance config exists
if not exist "%PACKAGE_DIR%\compliance_config\" (
    echo  [ERROR] Missing: %PACKAGE_DIR%\compliance_config\
    goto :error
)

echo  [OK] Pre-flight checks passed
echo.

REM Launch the TUI via the bundled embeddable Python runtime
pushd "%ROOT%"
"%PYTHON%" -m compliance_audit --tui %*
set "EXIT_CODE=%ERRORLEVEL%"
popd

if not %EXIT_CODE% EQU 0 (
    echo.
    echo  [ERROR] Exited with code %EXIT_CODE%. Review logs\debug.log for details.
    echo.
    pause
)

endlocal
exit /b %EXIT_CODE%

:error
echo.
echo  [FAILED] Cannot start - resolve the error above and try again.
echo.
pause
endlocal
exit /b 1
