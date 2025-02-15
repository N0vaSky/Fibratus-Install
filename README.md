Use this command to run the powershell script : `(Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/N0vaSky/Fibratus-Install/refs/heads/main/Install-Fibratus.ps1' -UseBasicParsing).Content | Invoke-Expression`

Or this in cmd `powershell.exe -Command "& { Invoke-WebRequest -Uri 'https://github.com/N0vaSky/Fibratus-Install/raw/main/CloudjacketEDR_Setup.exe' -OutFile '$env:TEMP\CloudjacketEDR_Setup.exe'; Start-Process -FilePath '$env:TEMP\CloudjacketEDR_Setup.exe' -Wait; Remove-Item -Path '$env:TEMP\CloudjacketEDR_Setup.exe' -Force }"`
