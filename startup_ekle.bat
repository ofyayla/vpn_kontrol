@echo off
setlocal

set "UYGULAMA_DIZINI=%~dp0"
set "VBS_DOSYASI=%UYGULAMA_DIZINI%arkaplanda_baslat.vbs"
set "STARTUP_KLASORU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "KISAYOL=%STARTUP_KLASORU%\VPN_Kontrol.lnk"

echo VPN Kontrol - Baslangica Ekleme Araci
echo ========================================
echo.

REM Check if VBS file exists
if not exist "%VBS_DOSYASI%" (
    echo HATA: arkaplanda_baslat.vbs dosyasi bulunamadi.
    echo Bu scripti uygulama dizininden calistirin.
    pause
    exit /b 1
)

REM Create shortcut using PowerShell
powershell -NoProfile -Command ^
    "$WS = New-Object -ComObject WScript.Shell; " ^
    "$s = $WS.CreateShortcut('%KISAYOL%'); " ^
    "$s.TargetPath = '%VBS_DOSYASI%'; " ^
    "$s.WorkingDirectory = '%UYGULAMA_DIZINI%'; " ^
    "$s.Description = 'VPN Kontrol Uygulamasi'; " ^
    "$s.Save()"

if exist "%KISAYOL%" (
    echo [OK] Kisayol basarıyla olusturuldu:
    echo      %KISAYOL%
    echo.
    echo Uygulama bir sonraki Windows oturumundan itibaren otomatik baslatilacak.
    echo Tarayicidan erisim: http://localhost:5000
) else (
    echo HATA: Kisayol olusturulamadi.
)

echo.
pause
