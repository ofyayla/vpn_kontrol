@echo off
cd /d "%~dp0"
echo VPN Kontrol Uygulamasi Baslatiliyor...
echo Tarayicidan erisebilirsiniz: http://localhost:5000
echo Pencereyi kapatirsaniz uygulama kapanir.
echo Arka planda calistirmak icin 'arkaplanda_baslat.vbs' dosyasini kullanin.
echo.
python app.py
pause
