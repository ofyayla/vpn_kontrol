@echo off
echo VPN Kontrol durduruluyor...
echo.

REM Method 1: Kill by port 5000 (Flask server)
echo Adim 1: Port 5000'deki islemi durdurma...
for /f "tokens=5" %%a in ('netstat -aon ^| find ":5000" ^| find "LISTENING"') do (
    echo Port 5000 PID bulundu: %%a
    taskkill /f /pid %%a 2>nul
    if errorlevel 1 (
        echo PID %%a durdurulamadi
    ) else (
        echo PID %%a basariyla durduruldu
    )
)

REM Method 2: Kill Python processes with app.py command line
echo.
echo Adim 2: Python app.py islemlerini durdurma...
for /f "tokens=2" %%a in ('wmic process where "commandline like '%%app.py%%' and name='python.exe'" get processid /format:list ^| find "ProcessId"') do (
    echo Python app.py PID bulundu: %%a
    taskkill /f /pid %%a 2>nul
    if errorlevel 1 (
        echo PID %%a durdurulamadi
    ) else (
        echo PID %%a basariyla durduruldu
    )
)

REM Method 3: Final check - kill by window title (legacy method)
echo.
echo Adim 3: Baslik ile kontrol...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Administrator:  VPN Kontrol*" 2>nul

echo.
echo ========================================
echo VPN Kontrol durdurma islemi tamamlandi.
echo ========================================
timeout /t 3

