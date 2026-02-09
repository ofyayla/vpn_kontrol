@echo off
echo VPN Kontrol durduruluyor...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Administrator:  VPN Kontrol*"
rem Eger window title bulamazsa genel python'u durdurmak riskli olabilir ama bu app icin mecbur
rem Daha guvenli bir yontem: port 5000'i kullanan PID'i bulup oldurmek

for /f "tokens=5" %%a in ('netstat -aon ^| find ":5000" ^| find "LISTENING"') do taskkill /f /pid %%a

echo.
echo Islem tamamlandi.
pause
