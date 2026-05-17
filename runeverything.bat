@echo off
title QuantumHop Launcher
color 0A

echo ============================================
echo        QuantumHop Full Stack Launcher
echo ============================================
echo.

:: Set the project root to the directory of this batch file
set PROJECT_ROOT=%~dp0
set VENV_ACTIVATE=%PROJECT_ROOT%venv\Scripts\activate.bat
set BACKEND_DIR=%PROJECT_ROOT%backend
set FRONTEND_DIR=%PROJECT_ROOT%frontend

:: ─── Kill any processes on our ports ──────────────────────────────────
echo [CLEANUP] Killing processes on ports 5000, 5010, 5173, 5555...

:: Port 5000 (Flask API)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5000 " ^| findstr "LISTENING"') do (
    echo   Killing PID %%a on port 5000
    taskkill /F /PID %%a >nul 2>&1
)

:: Port 5010 (Peer Socket)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5010 " ^| findstr "LISTENING"') do (
    echo   Killing PID %%a on port 5010
    taskkill /F /PID %%a >nul 2>&1
)

:: Port 5173 (Vite Frontend)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    echo   Killing PID %%a on port 5173
    taskkill /F /PID %%a >nul 2>&1
)

:: Port 5555 (UDP Discovery — kill any lingering process)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5555 "') do (
    echo   Killing PID %%a on port 5555
    taskkill /F /PID %%a >nul 2>&1
)

echo [CLEANUP] Done.
echo.

:: Check if venv exists
if not exist "%VENV_ACTIVATE%" (
    echo [ERROR] Virtual environment not found at: %VENV_ACTIVATE%
    echo Please create a venv first: python -m venv venv
    pause
    exit /b 1
)

:: Check if node_modules exists
if not exist "%FRONTEND_DIR%\node_modules" (
    echo [INFO] node_modules not found. Installing frontend dependencies...
    cd /d "%FRONTEND_DIR%"
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed!
        pause
        exit /b 1
    )
)

:: Install Python deps (in case new ones were added)
echo [INFO] Installing Python dependencies...
cd /d "%PROJECT_ROOT%"
call "%VENV_ACTIVATE%" && pip install -r requirements.txt -q

echo.
echo [1/2] Starting Backend (Flask=5000, Socket=5010) ...
start "QuantumHop - Backend" cmd /k "cd /d "%PROJECT_ROOT%" && call "%VENV_ACTIVATE%" && python -m backend.app"

:: Small delay to let backend start first
timeout /t 2 /nobreak >nul

echo [2/2] Starting Frontend (Vite) on http://localhost:5173 ...
start "QuantumHop - Frontend" cmd /k "cd /d "%FRONTEND_DIR%" && npm run dev"

echo.
echo ============================================
echo  Both servers are starting in new windows!
echo  Backend  : http://0.0.0.0:5000  (Flask API)
echo  Socket   : 0.0.0.0:5010  (P2P TCP)
echo  Frontend : http://localhost:5173
echo ============================================
echo.
echo  FIREWALL (run once as admin):
echo    netsh advfirewall firewall add rule name="QuantumHop API" dir=in action=allow protocol=TCP localport=5000
echo    netsh advfirewall firewall add rule name="QuantumHop Socket" dir=in action=allow protocol=TCP localport=5010
echo    netsh advfirewall firewall add rule name="QuantumHop Discovery" dir=in action=allow protocol=UDP localport=5555
echo.
echo Close this window or the individual server
echo windows to stop the servers.
echo.
pause
