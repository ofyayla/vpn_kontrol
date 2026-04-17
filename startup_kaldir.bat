@echo off
setlocal

set "STARTUP_KLASORU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "KISAYOL=%STARTUP_KLASORU%\VPN_Kontrol.lnk"

echo VPN Kontrol - Baslangictan Kaldir
echo ====================================
echo.

if exist "%KISAYOL%" (
    del "%KISAYOL%"
    echo [OK] Uygulama baslangictan kaldirildi.
) else (
    echo Uygulama zaten baslangica eklenmemis.
)

echo.
pause
