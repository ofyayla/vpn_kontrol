Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Get script directory
scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = scriptDir

' Get Python executable from config.json (silent, via temp file)
pythonCmd = "python"
configFile = scriptDir & "\config.json"
tmpFile = scriptDir & "\~python_cmd.tmp"
If FSO.FileExists(configFile) Then
    On Error Resume Next
    WshShell.Run "powershell -NoProfile -WindowStyle Hidden -Command ""(Get-Content '" & configFile & "' | ConvertFrom-Json).python_executable | Out-File '" & tmpFile & "' -Encoding ASCII""", 0, True
    If FSO.FileExists(tmpFile) Then
        Set f = FSO.OpenTextFile(tmpFile, 1)
        val = Trim(f.ReadLine())
        f.Close
        FSO.DeleteFile tmpFile
        If Len(val) > 0 Then pythonCmd = val
    End If
    On Error Goto 0
End If

' Check if Flask is installed (silent, no window)
exitCode = WshShell.Run(pythonCmd & " -c ""import flask""", 0, True)

' If Flask not found, show error with install command
If exitCode <> 0 Then
    installCmd = pythonCmd & " -m pip install -r requirements.txt"
    msg = "Gerekli kutuphaneler yuklenmemis!" & vbCrLf & vbCrLf & _
          "Uygulamanin calismasi icin Flask gerekli." & vbCrLf & vbCrLf & _
          "Tum kutuphaneleri yuklemek icin su komutu calistirin:" & vbCrLf & vbCrLf & _
          installCmd & vbCrLf & vbCrLf & _
          "Simdi kurulum penceresini acmak ister misiniz?"
    
    result = MsgBox(msg, vbYesNo + vbCritical, "VPN Kontrol - Eksik Kutuphane")
    
    If result = vbYes Then
        ' Open PowerShell with colorful install command
        psCmd = "Write-Host '================================================' -ForegroundColor DarkCyan; " & _
                "Write-Host '   VPN Kontrol - Kutuphane Kurulumu' -ForegroundColor Cyan; " & _
                "Write-Host '================================================' -ForegroundColor DarkCyan; " & _
                "Write-Host ''; " & _
                "Write-Host 'Asagidaki komutu calistirin:' -ForegroundColor Yellow; " & _
                "Write-Host ''; " & _
                "Write-Host '  " & installCmd & "' -ForegroundColor Green; " & _
                "Write-Host ''; " & _
                "Write-Host '================================================' -ForegroundColor DarkCyan"
        WshShell.Run "powershell -NoExit -Command """ & psCmd & """", 1, False
    End If
    WScript.Quit
End If

' All checks passed, run app in background
WshShell.Run "cmd /c cd /d """ & scriptDir & """ && " & pythonCmd & " app.py", 0, False

MsgBox "VPN Kontrol arka planda baslatildi!" & vbCrLf & vbCrLf & _
       "Web arayuzu: http://localhost:5000" & vbCrLf & _
       "Python: " & pythonCmd & vbCrLf & vbCrLf & _
       "NOT: Bazi ozellikleri kullanmak icin tum kutuphanelerin" & vbCrLf & _
       "yuklenmesi gerekebilir. Web arayuzunde uyari gosterilecektir." & vbCrLf & vbCrLf & _
       "Durdurmak icin 'durdur.bat' dosyasini calistirin.", _
       vbInformation, "VPN Kontrol - Baslatildi"

Set FSO = Nothing
Set WshShell = Nothing
