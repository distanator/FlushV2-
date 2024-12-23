@echo off
color a
color c
cls

:::                   _______________ _____  ______________  __
:::                  ___  ____/__  / __  / / /_  ___/__  / / /
:::                  __  /_   __  /  _  / / /_____ \__  /_/ / 
:::                  _  __/   _  /___/ /_/ / ____/ /_  __  /  
:::                  /_/      /_____/\____/  /____/ /_/ /_/  v2.0   
:::                      MADE BY DISTANATOR (RUN AS ADMIN)            

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A                   



pause
sfc /scannow
dism /online /cleanup-image /restorehealth
powercfg -h off
echo Cleaning Temporary Files and Cache...

del /q /f /s %TEMP%\*
del /q/f/s C:\Windows\Temp\*
del /q/f/s C:\Users\%username%\AppData\Local\Temp\*

echo Temporary files and cache cleaned.

echo Disabling Windows Animations and Visual Effects...

:: Disable animations in Windows

:: Disable menu animations (transitions when opening menus)
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

:: Set performance settings to "Best Performance" (disables most visual effects)
reg add "HKCU\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d "2" /f

:: Disable the smooth scrolling effect
reg add "HKCU\Control Panel\Desktop" /v "SmoothScroll" /t REG_SZ /d "0" /f

:: Disable taskbar thumbnail previews
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f

:: Disable animations in the Start menu
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableAnimations" /t REG_DWORD /d "1" /f

:: Apply the changes (to immediately affect the system)
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters

echo Animations have been disabled.
echo Disabling Fast Startup...

powercfg -h off
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

echo Fast Startup disabled.

Fsutil behavior query disabledeletenotify
netsh winsock reset
ipconfig /flushdns
echo Flushing DNS cache...
echo DNS cache flushed.
ping localhost
netsh Winsock reset
set /p choice=Do you want Ultimate Performance power plan? (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ySelected
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nSelected
) else (
    echo Invalid input! Please enter Y or N.
)

:ySelected
pause
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

echo Applied sucessfully!

timeout /t 2 /nobreak
goto nSelected
break

:nSelected
echo. optimizing powerplan...
powercfg -change -standby-timeout-ac 0
powercfg -change -monitor-timeout-ac 0
powercfg -setactive SCHEME_MAX
Optimizing powerplan completed
net stop wuauserv
net stop bits
del /f /s /q %windir%\SoftwareDistribution\Download\*.*
net start wuauserv
net start bits
netsh int ip reset
del /q /f /s %TEMP%\*
netsh interface tcp set global autotuninglevel=disabled
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable >nul 2>&1 
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable >nul 2>&1 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 400 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
timeout /t 2 /nobreak
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f









@echo off
set /p choice=Do you want to disable Windows Update service? (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)

:ysel
echo. Stopping updates until next reboot...
net stop wuauserv
sc config wuauserv start= disabled
:nsel


@echo off
set /p choice=Do you want to apply new DNS settings? (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)


:ysel
echo. changing dns to google dns...
netsh interface ip set dns name="Local Area Connection" source=static addr=none

netsh interface ip add dns name="Local Area Connection" addr=8.8.8.8 index=1
netsh interface ip add dns name="Local Area Connection" addr=8.8.4.4 index=2

netsh interface ip set dns name="Local Area Connection" source=dhcp

netsh interface ip set dns name="Ethernet" static 8.8.8.8
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2
goto nsel
break

:nsel
start ms-settings:gaming-gameMode
echo. search game mode and enable it.
timeout /t 2 /nobreak
echo.
echo. Press Enter, Services, Hide all Microsoft services and deselect whatever you don't need!
echo.

reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableFullscreenOptimizations /t REG_DWORD /d 0 /f

echo. Improving latency...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v TcpAckFrequency /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v TCPNoDelay /t REG_DWORD /d 1 /f
echo. Latency improved!

powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100

set /p choice=Do you want to disable search indexing? (not recommended) (Y/N):
if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)

:ysel
net stop "Windows Search"
sc config "WSearch" start= disabled


:nsel
pause



@echo off
set /p choice=Do you want to apply NVIDIA tweaks? (Nvidia only) (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)

:ysel

nvidia-smi -pm 1
nvidia-smi --auto-boost-default=0
nvidia-smi -i 0 --fan-speed 100
REG ADD "HKCU\Control Panel\Desktop" /v "DC_DONOTVSYNC" /t REG_DWORD /d 1 /f
nvidia-smi -pl 200
REG ADD "HKCU\Software\NVIDIA Corporation\Global" /v "PerfMode" /t REG_DWORD /d 1 /f
sc stop nvsync
sc config nvsync start= disabled
sc stop nvTelemetry
sc config nvTelemetry start= disabled
REG ADD "HKCU\Software\NVIDIA Corporation\Global" /v "TextureFilteringQuality" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Dwm" /v "GPUHardwareScheduling" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\NVIDIA Corporation\Global" /v "ShaderCache" /t REG_DWORD /d 0 /f
nvidia-smi -i 0 --clock-freq 2000
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "EnableFullScreenOptimizations" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Dwm" /v "GPUScheduler" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\NVIDIA Corporation\Global" /v "LowLatencyMode" /t REG_DWORD /d 1 /f

echo. NVIDIA tweaks applied!
pause	
:nsel




@echo off
set /p choice=Do you want to apply CPU & GPU tweaks? (AMD) (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)

:ysel
sc config wuauserv start= disabled
sc config sysmain start= disabled
sc config diagtrack start= disabled
wmic cpu set PowerManageable=false
reg add "HKCU\Software\Microsoft\DirectX" /v "PreferMaxPerf" /t REG_DWORD /d "1" /f
start "" "C:\Program Files\AMD\CNext\CNext\AMD Radeon Settings.exe"

pause
:nsel




@echo off
set /p choice=Do you want to apply CPU tweaks? (Intel) (Y/N): 

if /i "%choice%"=="Y" (
    echo You chose Yes!
goto ysel
) else if /i "%choice%"=="N" (
    echo You chose No!
goto nsel
) else (
    echo Invalid input! Please enter Y or N.
)

:ysel
taskkill /f /im "OneDrive.exe"
taskkill /f /im "Skype.exe"
taskkill /f /im "Teams.exe"
reg add "HKCU\Software\Discord" /v "HardwareAcceleration" /t REG_DWORD /d "0" /f
powercfg -attributes SUB_PROCESSOR CPUPowerPolicy -ATTRIB_HIDE
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPUPowerPolicy 0
powercfg -setactive SCHEME_CURRENT

pause
:nsel



msconfig

cls
color A

@echo off
echo.                               __  _                                                __     __       __
echo.  ____  ____  ___  _________ _/ /_(_)___  ____  _____   _________  ____ ___  ____  / /__  / /____  / /
echo./ __ \/ __ \/ _ \/ ___/ __ `/ __/ / __ \/ __ \/ ___/  / ___/ __ \/ __ `__ \/ __ \/ / _ \/ __/ _ \/ / 
echo./ /_/ / /_/ /  __/ /  / /_/ / /_/ / /_/ / / / (__  )  / /__/ /_/ / / / / / / /_/ / /  __/ /_/  __/_/  
echo.\____/ .___/\___/_/   \__,_/\__/_/\____/_/ /_/____/   \___/\____/_/ /_/ /_/ .___/_/\___/\__/\___(_)   
echo.    /_/                                                                  /_/                          
echo.                                    github.com/distanator - Flush V2
pause                                                                                                                  

pause>nul
