##########################################
# Windows 10 VDI Optimizer v 2.3         #
# Autor:  Tomek Kubiczek                 #
# Utworzono: 2017-09-29                  #
# Ostatnia aktualizacja: 2018-03-20      #
# �r�d�a: github, Technet, AutoIT        #
# Info: Dla wersji LTSB                  #
# Changelog:                             #
# 2018-03-16                             #
# HKCU zmienione na HKLM:\DEFAULT\       #
# Wyrzucone testpath - wrzucane na si��  #
# Dodany -Force do HKLM:\DEFAULT\        #
# 2018-03-19                             #
# Mapowanie ntuser.dat                   #
# 2018-03-20                             #
# Dodane oemlogo/oeminfo                 #
# 2018-03-21                             #
# poprawki efekt�w wizualizacji          #
# 2018-03-22                             #
# Ustawienia wst�pne wrzucone na pocz�tek#
##########################################
cls
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "# Tomek   | Windows 10 VDI Optimizer #" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black
    Write-Host "######################################" -BackgroundColor Yellow -ForegroundColor Black


    Write-Host "##########################" -BackgroundColor Green -ForegroundColor Black
    Write-Host "# Ustawienia wst�pne     #" -BackgroundColor Green -ForegroundColor Black
    Write-Host "##########################" -BackgroundColor Green -ForegroundColor Black

# Mapowanie ntuser.dat w HKLM:\DEFAULT\ i dodanie brakuj�cych kluczy.
    Write-Host "Mapowanie Default NTUSER.DAT" -BackgroundColor Black -ForegroundColor Yellow
    REG LOAD HKLM\DEFAULT C:\Users\Default\NTUSER.DAT

    Write-Host "Tworzenie brakuj�cych kluczy w NTUSER.DAT" -BackgroundColor Black -ForegroundColor Green
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force  | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\Control Panel\Desktop" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\Control Panel\Desktop\WindowMetrics" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\DWM" -Force | Out-Null
    New-Item -Path "HKLM:\DEFAULT\System\GameConfigStore" -Force | Out-Null 
    New-Item -Path "HKLM:\DEFAULT\Control Panel\Keyboard" -Force | Out-Null

    Write-Host "Tworzenie brakuj�cych kluczy Komputera" -BackgroundColor Black -ForegroundColor Green
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null 
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force| Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Force | Out-Null 

##########################################
# Prywatno��                             #
##########################################
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
    Write-Host "# Ustawienia prywatno�ci #" -BackgroundColor Black -ForegroundColor Green
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
# Telemetria
	Write-Host "Wy��czam telemetri�..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force

# Wi-Fi Sense

	Write-Host "Wy��czam Wi-Fi Sense..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -Force

# SmartScreen Filter
	Write-Host "Wy��czam SmartScreen Filter..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0 -Force
	
# Web Search in Start Menu
	Write-Host "Wy��czam Bing Search w Start Menu..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

#  Start Menu suggestions
	Write-Host "Wy��czam sugesti� w Menu Start..."   
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 -Force

# Location Tracking
	Write-Host "Wy��czam �ledzenie lokalizacji..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
# Automatic Maps updates
	Write-Host "Wy��czam aktualizacj� Bing Maps..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
# Feedback
	Write-Host "Wy��czam Feedback..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 -Force

# Advertising ID
	Write-Host "Wy��czam funkcj� Advertising ID..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force

# Cortana
	Write-Host "Wy��czam funkcj� Cortana..." 
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Error reporting - dyskusyjne
	Write-Host "Wy��czam Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1

# Restrict Windows Update P2P only to local network
	Write-Host "Ograniczam Windows Update P2P tylko dla sieci lokalnej..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1 -Force 
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3 -Force

# Remove AutoLogger file and restrict directory # zbiera logi na potrzeby wysy�ania do MS
	Write-Host "Wy��czam AutoLogger..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking Service
	Write-Host "Zatrzymuj� i wy��czam Us�ug� �ledzenia Diagnostyki..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled

# Stop and disable WAP Push Service
	Write-Host "Zatrzymuj� i wy��czam Us�ug� WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled

##########################################
# Service Tweaks                         #
##########################################
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
    Write-Host "#   Service Tweaks       #" -BackgroundColor Black -ForegroundColor Green
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
# Lower UAC level (disabling it completely would break apps)

	Write-Host "Wy��czam UAC..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

# Wy��czanie starego SMB 1.0 protocol
	Write-Host "Wy��czam protok� SMB 1.0..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable Windows Defender - do dyskusji
	Write-Host "Disabling Windows Defender..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue

# Disable offering of drivers through Windows Update - do dyskusji, na VDI nie powinno by� potrzebne
	Write-Host "Wy��czam aktualizacj� Sterownik�w za pomoc� Windows Update..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1 -Force

# Automatyczny restart po Windows Update

	Write-Host "Wy��czam automatyczny restart po Windows Update..."

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0 -Force

# Wy��czanie Home Groups services

	Write-Host "Wy��czam us�ugi grupy roboczej..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled

# Remote Assistance - do dyskusji

	Write-Host "Wy��czam Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 

# Autoplay

	Write-Host "Wy��czam Autoplay..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 -Force

# Autorun for all drives

	Write-Host "Wy��czam Autorun dla wszystkich dysk�w..."

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 -Force

# scheduled defragmentation task

	Write-Host "Wy��czam zaplanowan� defragmentacj�..."
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null

# Stop and disable Superfetch service - do dyskusji

	Write-Host "Zatrzymuj� i wy��czam Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled

# Stop and disable Windows Search indexing service

	Write-Host "Wy��czam Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
# Disable Hibernation - do dyskusji

	Write-Host "Wy��czam Hibernacj�..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

# Disable Fast Startup do dyskusji

	Write-Host "Wy��czam Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

##########################################
# Ustawienia wygl�du                     #
##########################################
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
    Write-Host "#   Ustawienia wygl�du   #" -BackgroundColor Black -ForegroundColor Green
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green

# Disable Action Center - do dyskusji, wydaje mi si�, �e nic nie wnosi na VDI
	Write-Host "Wy��czam Action Center..."   

	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 
# Disable Lock screen - do dyskusji
	Write-Host "Disabling Lock screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Hide network options from Lock Screen - do dyskusji
	Write-Host "Ukrywam opcje sieciowe z okna logowania..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1

# Hide shutdown options from Lock Screen - do dyskusji

	Write-Host "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0

# Show file operations details
	Write-Host "Ustawiam widok szczeg�owy w Eksploratorze plik�w..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 -Force

# Hide Taskbar Search button / box
	Write-Host "Ukrywam Szukaj z paska..." 
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 -Force

# Hide Task View button
	Write-Host "Ukrywam Task View button..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 -Force

# Show small icons in taskbar
	Write-Host "Optymalizuj� pasek zada�..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1 -Force

# Show titles in taskbar
	Write-Host "W��czam etykiery w pasku zada�..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1 -Force
# Hide Taskbar People icon
	Write-Host "Ukrywam People icon..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 -Force
# Show all tray icons
	Write-Host "W��czam wszystkie ikony w trayu..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 -Force
# Hide known file extensions
	Write-Host "Ukrywam rozszerzenia plik�w..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1 -Force
# Hide sync provider notifications
	Write-Host "Ukrywam sync provider notifications..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 -Force
# Hide recently and frequently used item shortcuts in Explorer
	Write-Host "Wy��czam skr�ty do ostatnio otwieranych dokument�w..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -Force
# Change default Explorer view to This PC
	Write-Host "Zamieniam Explorer na Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 -Force
# Show This PC shortcut on desktop
	Write-Host "Dodaj� skr�t Ten Komputer na pulpit..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
# Show Desktop icon in This PC
	Write-Host "W��czam ikon� Pulpit w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
# Show Documents icon in This PC
	Write-Host "W��czam ikon� Dokumenty w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
# Show Downloads icon in This PC
	Write-Host "W��czam ikon� Pobrane w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
# Hide Music icon from This PC
	Write-Host "Usuwam ikon� Muzyka w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
# Hide Pictures icon from This PC

	Write-Host "Usuwam ikon� Obrazy w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

# Hide Videos icon from This PC

	Write-Host "Usuwam ikon� Filmy w Ten Komputer..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
# Efekty wizualne
	Write-Host "Ustawiam efekty wizualne dla lepszej wydajno�ci..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKLM:\DEFAULT\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

# Disable thumbnails, show only file extension icons

	Write-Host "Wy��czam miniaturki..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1

# Disable creation of Thumbs.db thumbnail cache files

	Write-Host "Wy��czam tworzenie Thumbs.db..."
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1

##########################################
# Aplikacje                              #
##########################################

    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green
    Write-Host "#       Aplikacje        #" -BackgroundColor Black -ForegroundColor Green
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Green

# Wy��czanie OneDrive

	Write-Host "Wy��cza OneDrive..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 -Force

# Uninstall default Microsoft applications - tylko dla W10Pro dla LTSB prewencyjnie

	Write-Host "Uninstalling default Microsoft applications..."
	Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage

# Disable installation of consumer experience applications
	Write-Host "Disabling installation of consumer experience applications..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force

# Funkcje Xbox
	Write-Host "Wy��czam Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Set-ItemProperty -Path "HKLM:\DEFAULT\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force

# Windows Media Player
	Write-Host "Usuwam Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Work Folders Client 
	Write-Host "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Disable search for app in store for unknown extensions
	Write-Host "Disabling search for app in store for unknown extensions..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 -Force
# Wy��czanie 'How do you want to open this file?' prompt
	Write-Host "Disabling 'How do you want to open this file?' prompt..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1 -Force

##########################################
# Dedykowane pod VDI                     #
##########################################

    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Yellow
    Write-Host "#     Opcje pod VDI      #" -BackgroundColor Black -ForegroundColor Yellow
    Write-Host "##########################" -BackgroundColor Black -ForegroundColor Yellow

# Plan zasilania
Write-Host "Ustawiam plan zasilania na wysoka wydajno��..." -ForegroundColor Green
POWERCFG -SetActive '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'

#Bluetooth
Write-Host "Wy��czam Bluetooth Support Service..."
Set-Service bthserv -StartupType Disabled

#Bluetooth HandsFree
Write-Host "Disabling Bluetooth Handsfree Service..."
Set-Service BthHFSrv -StartupType Disabled

# Bitlocker
Write-Host "Wy��czam Bitlocker Drive Encryption Service..." 
Set-Service BDESVC -StartupType Disabled

#Windows Backup
Write-Host "Wy��czam Block Level Backup Engine Service..." 
Set-Service wbengine -StartupType Disabled

#ALG.exe Firewall
Write-Host "Wy��czam Application Layer Gateway Service..." 
Set-Service ALG -StartupType Disabled

#BranchCache
Write-Host "Wy��czam BranchCache Service..."
Set-Service PeerDistSvc -StartupType Disabled

#Szukaj - Utrzymuje aktualn� list� komputer�w w sieci i dostarcza j� do komputer�w wyznaczonych jako przegl�darki. Je�li ta us�uga zostanie zatrzymana, lista nie b�dzie aktualizowana ani zachowywana. Je�li ta us�uga zostanie wy��czona, wszelkie us�ugi jawnie od niej zale�ne przestan� si� uruchamia�.
Write-Host "Wy��czam Computer Browser Service..."
Set-Service Browser -StartupType Disabled

#Mened�er konfiguracji urz�dze� - Umo�liwia wykrywanie, pobieranie i instalowanie oprogramowania zwi�zanego z urz�dzeniami. W przypadku wy��czenia tej us�ugi urz�dzenia mog� by� konfigurowane za pomoc� nieaktualnego oprogramowania i nie dzia�a� poprawnie.
Write-Host "Wy��czam Device Setup Manager Service..." -ForegroundColor Cyan
Set-Service DsmSvc -StartupType Disabled

#Us�uga Zasady diagnostyki umo�liwia wykrywanie problem�w, rozwi�zywanie problem�w i rozpoznawanie sk�adnik�w systemu Windows. Je�li ta us�uga zostanie zatrzymana, diagnostyka nie b�dzie ju� dzia�a�.
Write-Host "Wy��czam Diagnostic Policy Service..."
Set-Service DPS -StartupType Disabled

#Host us�ugi diagnostyki
Write-Host "Wy��czam Diagnostic Service Host Service..."
Set-Service WdiServiceHost -StartupType Disabled

#Host systemu diagnostyki
Write-Host "Wy��czam Diagnostic System Host Service..."
Set-Service WdiSystemHost -StartupType Disabled

#�rodowiska i telemetria po��czonego u�ytkownika
Write-Host "Wy��czam Diagnostics Tracking Service..."
Set-Service DiagTrack -StartupType Disabled

#EFS
Write-Host "Wy��czam EFS Service..."
Set-Service EFS -StartupType Disabled

#Protok� uwierzytelniania rozszerzonego (EAP)
Write-Host "Wy��czam Protok� uwierzytelniania rozszerzonego (EAP)..."
Set-Service Eaphost -StartupType Disabled

#Faksowanie
Write-Host "Wy��czam Faksowanie..."
Set-Service Fax -StartupType Disabled

#Publikacja zasob�w odnajdowania funkcji
Write-Host "Wy��czam Publikacja zasob�w odnajdowania funkcji..." 
Set-Service FDResPub -StartupType Disabled

#Udost�pnianie po��czenia internetowego (ICS)
Write-Host "Wy��czam Internet Connection Sharing (ICS) Service..." 
Set-Service SharedAccess -StartupType Disabled

#Asystent logowania za pomoc� konta Microsoft
Write-Host "Wy��czam Microsoft Account Sign-in Assistant Service..."
Set-Service wlidsvc -StartupType Disabled

#Us�uga inicjatora iSCSI firmy Microsoft
Write-Host "Wy��czam Microsoft iSCSI Initiator Service..." 
Set-Service MSiSCSI -StartupType Disabled

#Dostawca kopiowania w tle oprogramowania firmy Microsoft
Write-Host "Wy��czam Microsoft Software Shadow Copy Provider Service..."
Set-Service swprv -StartupType Disabled

#Miejsca do magazynowania firmy Microsoft � SMP
Write-Host "Wy��czam Microsoft Storage Spaces SMP Service..."
Set-Service smphost -StartupType Disabled

#Offline Files
Write-Host "Wy��czam Offline Files Service..."
Set-Service CscService -StartupType Disabled

#Optymalizowanie dysk�w
Write-Host "Wy��czam Optimize drives Service..."
Set-Service defragsvc -StartupType Disabled

#Us�uga Asystent zgodno�ci program�w
Write-Host "Wy��czam Us�uga Asystent zgodno�ci program�w..."
Set-Service PcaSvc -StartupType Disabled

#Quality Windows Audio Video Experience
Write-Host "Wy��czam Quality Windows Audio Video Experience Service..."
Set-Service QWAVE -StartupType Disabled

#Us�uga trybu pokazowego
Write-Host "Wy��czam Us�uga trybu pokazowego..." 
Set-Service RetailDemo -StartupType Disabled

#Us�uga Protok� SSTP
Write-Host "Wy��czam Us�uga Protok� SSTP..."
Set-Service SstpSvc -StartupType Disabled

#Us�uga danych czujnik�w
Write-Host "Wy��czam Us�uga danych czujnik�w..." 
Set-Service SensorDataService -StartupType Disabled

#Us�uga monitorowania czujnik�w
Write-Host "Wy��czam Us�uga monitorowania czujnik�w..."
Set-Service SensrSvc -StartupType Disabled

#Us�uga czujnik�w
Write-Host "Wy��czam Us�uga czujnik�w..."
Set-Service SensorService -StartupType Disabled

#Wykrywanie sprz�tu pow�oki
Write-Host "Wy��czam Wykrywanie sprz�tu pow�oki..."
Set-Service ShellHWDetection -StartupType Disabled

#SNMP Trap
Write-Host "Wy��czam SNMP Trap Service..."
Set-Service SNMPTRAP -StartupType Disabled

#Weryfikator punktowy | Weryfikuje potencjalne uszkodzenia systemu plik�w.
Write-Host "Wy��czam Weryfikator punktowy..."
Set-Service svsvc -StartupType Disabled

#Odnajdywanie SSDP
Write-Host "Wy��czam Odnajdywanie SSDP..."
Set-Service SSDPSRV -StartupType Disabled

#Zdarzenia pozyskiwania obraz�w nieruchomych
Write-Host "Wy��czam Zdarzenia pozyskiwania obraz�w nieruchomych..."
Set-Service WiaRpc -StartupType Disabled

#Telefonia | Zapewnia obs�ug� telefonii API (TAPI) dla program�w steruj�cych urz�dzeniami telefonii na komputerze lokalnym i, za po�rednictwem sieci LAN, na serwerach, na kt�rych dzia�a ta us�uga.
Write-Host "Wy��czam us�ug� Telefonia..."
Set-Service TapiSrv -StartupType Disabled

#Tematy Windows
Write-Host "Wy��czam tematy Windows..."
Set-Service Themes -StartupType Disabled

#UPnP
Write-Host "Wy��czam UPnP..."
Set-Service upnphost -StartupType Disabled

#VSS
Write-Host "Wy��czam Volume Shadow Copy..."
Set-Service VSS -StartupType Disabled

#Po��cz teraz w systemie Windows � Rejestrator konfiguracji
Write-Host "Wy��czam Po��cz teraz w systemie Windows � Rejestrator konfiguracji..." 
Set-Service wcncsvc -StartupType Disabled

#Windows Image Acquisition (WIA)
Write-Host "Wy��czam Windows Image Acquisition (WIA) Service..."
Set-Service stisvc -StartupType Disabled

#Us�uga hotspotu mobilnego
Write-Host "Wy��czam Us�uga hotspotu mobilnego..."
Set-Service icssvc -StartupType Disabled

#Autokonfiguracja sieci WLAN
Write-Host "Wy��czam Autokonfiguracja sieci WLAN..." 
Set-Service WlanSvc -StartupType Disabled

#Automatyczne konfigurowanie bezprzewodowej sieci WAN
Write-Host "Wy��czam Automatyczne konfigurowanie bezprzewodowej sieci WAN..."
Set-Service WwanSvc -StartupType Disabled


####################################################################################
# Reconfigure / Change Services:                                                   #
# zapo�yczone z :                                                                  #
# https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1                      #                                
####################################################################################

Write-Host "Configuring Network List Service to start Automatic..." 
Set-Service netprofm -StartupType Automatic

Write-Host "Configuring Windows Update Service to run in standalone svchost..." 
sc.exe config wuauserv type= own


# Configure WMI - do zweryfikowania jak to jest z sccm'em:
# Write-Host "Modifying WMI Configuration..." 
# $oWMI=get-wmiobject -Namespace root -Class __ProviderHostQuotaConfiguration
# $oWMI.MemoryPerHost=768*1024*1024
# $oWMI.MemoryAllHosts=1536*1024*1024
# $oWMI.put()
# Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt -Name 'Group' -Value 'COM Infrastructure'
# winmgmt /standalonehost

# Wy��czenie hibernacji
    Write-Host "Wy��czam hibernacj�..."
    POWERCFG -h off

# Large Send Offload
    Write-Host "Wy��czam TCP Large Send Offload..." -ForegroundColor Green
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name 'DisableTaskOffload' -PropertyType DWORD -Value '1' -Force | Out-Null

# Przywracanie systemu
    Write-Host "Wy��czam Przywracanie systemu..."
    Disable-ComputerRestore -Drive "C:\"

# Disable NTFS Last Access Timestamps
    Write-Host "Wy��czam NTFS Last Access Timestamps..."
    FSUTIL behavior set disablelastaccess 1 | Out-Null

#Memory Dumps
    Write-Host "Wy��czam zrzuty pami�ci..."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value '1' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Value '0' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Value '0' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Value '1' -Force

# Czas oczekiwania na us�ugi:
    Write-Host "Zwi�kszam czas oczekiwania na us�ugi do 3 minut..."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Value '180000' -Force

#I/O dysku
    Write-Host "Zwi�kszam I/O dysku do 200 sekund..." -ForegroundColor Cyan
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name 'TimeOutValue' -Value '200' -Force

# IE First Run Wizard:
    Write-Host "Wy��czam kreator pierwszego uruchomienia IE..."
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force | Out-Null

# Usuwanie OneDrive - Not applicable to Server

	Write-Host "Usuwanie OneDrive..."
	Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Sleep -s 3
	Stop-Process -Name explorer -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Stary Photo Viewer dla bmp, gif, jpg, png and tif

	Write-Host "Setting Photo Viewer association for bmp, gif, jpg, png and tif..." -ForegroundColor Cyan
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}

# Dodawanie Photo Viewer do "Otw�rz za pomoc�..."

	Write-Host "Dodaj� Photo Viewer to `"Otw�rz za pomoc�...`"" -ForegroundColor Cyan
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

# Dodawanie OEMLOGO/OEMINFO"
    Write-Host "Dodaj� OEMLOGO/OEMINFO - Advicom " -ForegroundColor Green
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Logo" -Type String -Value "C:\Windows\System32\Sysprep\oemlogo.bmp" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Manufacturer" -Type String -Value "Your Org. Inc." -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "SupportHours" -Type String -Value "24/7/365" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "SupportPhone" -Type String -Value "Phone Number" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "SupportURL" -Type String -Value "http://www.github.com/qbicone" -Force

#Write-Host "Czyszczenie obrazu Windows"
#DISM /online /Cleanup-Image /SPSuperseded
    Write-Host "Odmontowywanie Default NTUSER.DAT" -BackgroundColor Black -ForegroundColor Yellow 
    REG UNLOAD HKLM\DEFAULT

##########################################
# Koniec                                 #
##########################################

    Write-Host "##########################" -BackgroundColor Yellow -ForegroundColor Red
    Write-Host "#     Koniec             #" -BackgroundColor Yellow -ForegroundColor Red
    Write-Host "##########################" -BackgroundColor Yellow -ForegroundColor Red