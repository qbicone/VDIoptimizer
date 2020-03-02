@ECHO OFF
rem All Files place in %SystemRoot%\system32\sysprep\
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SystemRoot%\system32\sysprep\Win10_VDI.ps1"
echo Maszyna utworzona: %date%,%time% >> %SystemRoot%\system32\sysprep\log1.log
echo KONIEC