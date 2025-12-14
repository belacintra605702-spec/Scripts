# =============================================================================
# ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION
# =============================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`nAdministrative privileges required..." -ForegroundColor Yellow
    Write-Host "Requesting elevation via UAC..." -ForegroundColor Gray
    
    try {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($args.Count -gt 0) {
            $arguments += " " + ($args -join " ")
        }
        
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
        exit
    }
    catch {
        Write-Host "`nERROR: Failed to elevate privileges!" -ForegroundColor Red
        Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        Write-Host "Error details: $_" -ForegroundColor Gray
        pause
        exit 1
    }
}

# Verification that we're running as admin (after potential elevation)
Write-Host "`nRunning with administrative privileges..." -ForegroundColor Green
# =============================================================================

# =============================================================================
# Script: 02B_UNDO_Safe_Clean_Drivers.ps1
# Purpose: Restore settings modified by 02A_Safe_Clean_Drivers.ps1
# Requirements: Run as Administrator, Windows 11
# Encoding: ANSI
# Note: Some actions are not reversible and will be reported only
# =============================================================================

#region INITIALIZATION
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "DRIVER CLEANUP RESTORATION UTILITY" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script will restore settings modified by 02A script:" -ForegroundColor White
Write-Host "  - Re-enable disabled drivers (REVERSIBLE)" -ForegroundColor Green
Write-Host "  - Restore service startup types (REVERSIBLE)" -ForegroundColor Green
Write-Host "  - Report removed software (NOT REVERSIBLE)" -ForegroundColor Yellow
Write-Host "  - Report removed drivers (NOT REVERSIBLE)" -ForegroundColor Yellow
Write-Host "  - Report ghost registry cleanup (NOT REVERSIBLE)" -ForegroundColor Yellow
Write-Host "`nIMPORTANT: Manual steps may be required after restoration" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan

# Find log files
$logFolder = "$env:USERPROFILE\Documents\DriverCleanupLogs"

if (-not (Test-Path $logFolder)) {
    Write-Host "`nERROR: Log folder not found at: $logFolder" -ForegroundColor Red
    Write-Host "Please run 02A_Safe_Clean_Drivers.ps1 first." -ForegroundColor Yellow
    pause
    exit 1
}

$logFiles = Get-ChildItem "$logFolder\DriverCleanup_*.txt" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending

if ($logFiles.Count -eq 0) {
    Write-Host "`nERROR: No cleanup log files found in: $logFolder" -ForegroundColor Red
    Write-Host "Please run 02A_Safe_Clean_Drivers.ps1 first to create a log file." -ForegroundColor Yellow
    pause
    exit 1
}

# Display available log files
Write-Host "`nFound $($logFiles.Count) cleanup log file(s):" -ForegroundColor White
Write-Host "-"*70 -ForegroundColor Gray

for ($i = 0; $i -lt $logFiles.Count; $i++) {
    $size = [math]::Round($logFiles[$i].Length / 1KB, 2)
    Write-Host "  [$($i+1)] $($logFiles[$i].Name)" -ForegroundColor Cyan
    Write-Host "      Date: $($logFiles[$i].LastWriteTime)" -ForegroundColor Gray
    Write-Host "      Size: $size KB" -ForegroundColor Gray
}

# Select log file
$selectedIndex = 0
if ($logFiles.Count -gt 1) {
    Write-Host "`nSelect log file to restore from:" -ForegroundColor White
    Write-Host "  - Enter number (1-$($logFiles.Count))" -ForegroundColor Gray
    Write-Host "  - Press Enter for most recent" -ForegroundColor Gray
    
    $input = Read-Host "`nYour selection"
    if ($input -ne '' -and $input -match '^\d+$') {
        $num = [int]$input
        if ($num -ge 1 -and $num -le $logFiles.Count) {
            $selectedIndex = $num - 1
        }
    }
}

$logFile = $logFiles[$selectedIndex].FullName
Write-Host "`nSelected: $($logFiles[$selectedIndex].Name)" -ForegroundColor Green

# Read and parse log file
Write-Host "`nParsing log file..." -ForegroundColor Cyan

try {
    $logContent = Get-Content $logFile -Raw -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Could not read log file - $_" -ForegroundColor Red
    pause
    exit 1
}

# Initialize tracking arrays
$softwareRemoved = @()
$driversRemoved = @()
$driversDisabled = @()
$driverStoreCleanup = @()
$ghostRegistryCleaned = @()
$servicesOptimized = @()
$cacheWasCleaned = $false
$cacheSize = 0

# Parse log content
$lines = $logContent -split "`n"
$currentSection = ""

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i].Trim()
    
    if ($line -match "^SOFTWARE REMOVED: (\d+)") {
        $currentSection = "SOFTWARE"
    }
    elseif ($line -match "^DRIVERS REMOVED: (\d+)") {
        $currentSection = "DRIVERS_REMOVED"
    }
    elseif ($line -match "^DRIVERS DISABLED: (\d+)") {
        $currentSection = "DRIVERS_DISABLED"
    }
    elseif ($line -match "^DRIVER STORE CLEANUP: (\d+)") {
        $currentSection = "DRIVER_STORE"
    }
    elseif ($line -match "^GHOST REGISTRY ENTRIES CLEANED: (\d+)") {
        $currentSection = "GHOST_REGISTRY"
    }
    elseif ($line -match "^SERVICES OPTIMIZED: (\d+)") {
        $currentSection = "SERVICES"
    }
    elseif ($line -match "^WINDOWS UPDATE CACHE:") {
        $currentSection = "CACHE"
    }
    elseif ($line -match "^\s+-\s+(.+)$") {
        $content = $matches[1].Trim()
        
        switch ($currentSection) {
            "SOFTWARE" {
                $softwareRemoved += $content
            }
            "DRIVERS_REMOVED" {
                if ($content -match "^(.+?)\s*\(INF:\s*(.+?)\)") {
                    $driversRemoved += [PSCustomObject]@{
                        Name = $matches[1].Trim()
                        INF = $matches[2].Trim()
                    }
                }
            }
            "DRIVERS_DISABLED" {
                $driversDisabled += $content
            }
            "DRIVER_STORE" {
                $driverStoreCleanup += $content
            }
            "GHOST_REGISTRY" {
                $ghostRegistryCleaned += $content
            }
            "SERVICES" {
                if ($content -match "^(.+?):(.+?)->(.+?)$") {
                    $servicesOptimized += [PSCustomObject]@{
                        Name = $matches[1].Trim()
                        OriginalStartup = $matches[2].Trim()
                        NewStartup = $matches[3].Trim()
                    }
                }
            }
        }
    }
    elseif ($line -match "Cleaned:\s*(True|False)" -and $currentSection -eq "CACHE") {
        $cacheWasCleaned = $matches[1] -eq "True"
    }
    elseif ($line -match "Size freed:\s*([\d.]+)\s*MB" -and $currentSection -eq "CACHE") {
        $cacheSize = [double]$matches[1]
    }
}

# Display summary
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "LOG FILE SUMMARY" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White
Write-Host "Software removed: $($softwareRemoved.Count)" -ForegroundColor $(if ($softwareRemoved.Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Drivers removed: $($driversRemoved.Count)" -ForegroundColor $(if ($driversRemoved.Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Drivers disabled: $($driversDisabled.Count)" -ForegroundColor $(if ($driversDisabled.Count -gt 0) { "Green" } else { "Gray" })
Write-Host "Driver store cleaned: $($driverStoreCleanup.Count)" -ForegroundColor $(if ($driverStoreCleanup.Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Ghost registry cleaned: $($ghostRegistryCleaned.Count)" -ForegroundColor $(if ($ghostRegistryCleaned.Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Services optimized: $($servicesOptimized.Count)" -ForegroundColor $(if ($servicesOptimized.Count -gt 0) { "Green" } else { "Gray" })
Write-Host "Cache cleaned: $(if ($cacheWasCleaned) { "Yes ($cacheSize MB)" } else { "No" })" -ForegroundColor $(if ($cacheWasCleaned) { "Yellow" } else { "Gray" })

Write-Host "`n" + "-"*70 -ForegroundColor Gray
Write-Host "RESTORATION CAPABILITIES:" -ForegroundColor White
Write-Host "  CAN BE RESTORED:" -ForegroundColor Green
Write-Host "    - Drivers disabled: $($driversDisabled.Count) items" -ForegroundColor Green
Write-Host "    - Services optimized: $($servicesOptimized.Count) items" -ForegroundColor Green
Write-Host "  CANNOT BE RESTORED (will be reported only):" -ForegroundColor Yellow
Write-Host "    - Software removed: $($softwareRemoved.Count) items" -ForegroundColor Yellow
Write-Host "    - Drivers removed: $($driversRemoved.Count) items" -ForegroundColor Yellow
Write-Host "    - Driver store cleanup: $($driverStoreCleanup.Count) items" -ForegroundColor Yellow
Write-Host "    - Ghost registry: $($ghostRegistryCleaned.Count) items" -ForegroundColor Yellow
Write-Host "-"*70 -ForegroundColor Gray

# Confirmation
Write-Host "`n" + "!"*70 -ForegroundColor Yellow
Write-Host "CONFIRMATION REQUIRED" -ForegroundColor Yellow
Write-Host "!"*70 -ForegroundColor Yellow
Write-Host "This script will:" -ForegroundColor White
Write-Host "  1. Re-enable $($driversDisabled.Count) disabled drivers" -ForegroundColor White
Write-Host "  2. Restore $($servicesOptimized.Count) services to original startup types" -ForegroundColor White
Write-Host "  3. Provide report on non-reversible actions" -ForegroundColor White
Write-Host "!"*70 -ForegroundColor Yellow

$confirm = Read-Host "`nType 'YES' (in uppercase) to proceed"
if ($confirm -ne 'YES') {
    Write-Host "`nRestoration cancelled by user." -ForegroundColor Yellow
    pause
    exit 0
}
#endregion

#region STEP 1: RE-ENABLE DISABLED DRIVERS
if ($driversDisabled.Count -gt 0) {
    Write-Host "`n" + "="*70 -ForegroundColor White
    Write-Host "STEP 1: RE-ENABLING DISABLED DRIVERS" -ForegroundColor White
    Write-Host "="*70 -ForegroundColor White
    
    $enabledCount = 0
    $failedCount = 0
    
    foreach ($driverName in $driversDisabled) {
        Write-Host "`n  Processing: $driverName" -ForegroundColor Cyan
        
        try {
            # Find device by friendly name
            $devices = Get-PnpDevice | Where-Object { 
                $_.FriendlyName -like "*$driverName*" -or 
                $_.Name -like "*$driverName*"
            }
            
            if ($devices) {
                foreach ($device in $devices) {
                    if ($device.Status -eq "Error" -or $device.Status -eq "Disabled") {
                        try {
                            Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop
                            Write-Host "    SUCCESS: Driver enabled" -ForegroundColor Green
                            $enabledCount++
                        }
                        catch {
                            Write-Host "    WARNING: Could not enable - $_" -ForegroundColor Yellow
                            $failedCount++
                        }
                    }
                    else {
                        Write-Host "    INFO: Driver already enabled" -ForegroundColor Gray
                        $enabledCount++
                    }
                }
            }
            else {
                Write-Host "    WARNING: Device not found (may have been removed)" -ForegroundColor Yellow
                $failedCount++
            }
        }
        catch {
            Write-Host "    ERROR: Failed to process - $_" -ForegroundColor Red
            $failedCount++
        }
    }
    
    Write-Host "`n  Summary:" -ForegroundColor White
    Write-Host "    Successfully enabled: $enabledCount" -ForegroundColor Green
    Write-Host "    Failed/Not found: $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Yellow" } else { "Gray" })
}
else {
    Write-Host "`n" + "="*70 -ForegroundColor White
    Write-Host "STEP 1: RE-ENABLING DISABLED DRIVERS" -ForegroundColor White
    Write-Host "="*70 -ForegroundColor White
    Write-Host "`n  No drivers were disabled - Skipping" -ForegroundColor Gray
}
#endregion

#region STEP 2: RESTORE SERVICE STARTUP TYPES
if ($servicesOptimized.Count -gt 0) {
    Write-Host "`n" + "="*70 -ForegroundColor White
    Write-Host "STEP 2: RESTORING SERVICE STARTUP TYPES" -ForegroundColor White
    Write-Host "="*70 -ForegroundColor White
    
    $restoredCount = 0
    $failedCount = 0
    
    foreach ($service in $servicesOptimized) {
        Write-Host "`n  Restoring: $($service.Name)" -ForegroundColor Cyan
        Write-Host "    Original: $($service.OriginalStartup)" -ForegroundColor Gray
        Write-Host "    Current: $($service.NewStartup)" -ForegroundColor Gray
        
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction Stop
            
            # Restore to original startup type
            Set-Service -Name $service.Name -StartupType $service.OriginalStartup -ErrorAction Stop
            Write-Host "    SUCCESS: Restored to $($service.OriginalStartup)" -ForegroundColor Green
            $restoredCount++
        }
        catch {
            Write-Host "    ERROR: Failed to restore - $_" -ForegroundColor Red
            $failedCount++
        }
    }
    
    Write-Host "`n  Summary:" -ForegroundColor White
    Write-Host "    Successfully restored: $restoredCount" -ForegroundColor Green
    Write-Host "    Failed: $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Yellow" } else { "Gray" })
}
else {
    Write-Host "`n" + "="*70 -ForegroundColor White
    Write-Host "STEP 2: RESTORING SERVICE STARTUP TYPES" -ForegroundColor White
    Write-Host "="*70 -ForegroundColor White
    Write-Host "`n  No services were modified - Skipping" -ForegroundColor Gray
}
#endregion

#region STEP 3: REPORT NON-REVERSIBLE ACTIONS
Write-Host "`n" + "="*70 -ForegroundColor Yellow
Write-Host "STEP 3: NON-REVERSIBLE ACTIONS REPORT" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Yellow

$hasNonReversible = $false

# Software removed
if ($softwareRemoved.Count -gt 0) {
    $hasNonReversible = $true
    Write-Host "`nSOFTWARE REMOVED (Cannot be restored automatically):" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    foreach ($sw in $softwareRemoved) {
        Write-Host "  - $sw" -ForegroundColor Gray
    }
    Write-Host "`n  ACTION REQUIRED:" -ForegroundColor White
    Write-Host "    To reinstall this software, visit the ACER support website" -ForegroundColor Gray
    Write-Host "    or use the original installation media." -ForegroundColor Gray
}

# Drivers removed
if ($driversRemoved.Count -gt 0) {
    $hasNonReversible = $true
    Write-Host "`nDRIVERS REMOVED (Cannot be restored automatically):" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    foreach ($drv in $driversRemoved) {
        Write-Host "  - $($drv.Name)" -ForegroundColor Gray
        Write-Host "    INF: $($drv.INF)" -ForegroundColor DarkGray
    }
    Write-Host "`n  ACTION REQUIRED:" -ForegroundColor White
    Write-Host "    1. Reboot your computer" -ForegroundColor Gray
    Write-Host "    2. Windows will automatically detect missing drivers" -ForegroundColor Gray
    Write-Host "    3. Run Windows Update to reinstall drivers" -ForegroundColor Gray
    Write-Host "    4. Check Device Manager for any missing devices" -ForegroundColor Gray
}

# Driver store cleanup
if ($driverStoreCleanup.Count -gt 0) {
    $hasNonReversible = $true
    Write-Host "`nDRIVER STORE CLEANUP (Cannot be restored):" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    Write-Host "  Old driver versions removed: $($driverStoreCleanup.Count)" -ForegroundColor Gray
    Write-Host "`n  INFO:" -ForegroundColor White
    Write-Host "    These were old/duplicate driver versions." -ForegroundColor Gray
    Write-Host "    The newest versions were kept." -ForegroundColor Gray
    Write-Host "    Windows Update will download drivers if needed." -ForegroundColor Gray
}

# Ghost registry cleanup
if ($ghostRegistryCleaned.Count -gt 0) {
    $hasNonReversible = $true
    Write-Host "`nGHOST REGISTRY ENTRIES CLEANED (Cannot be restored):" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    Write-Host "  Entries removed: $($ghostRegistryCleaned.Count)" -ForegroundColor Gray
    Write-Host "`n  INFO:" -ForegroundColor White
    Write-Host "    These were orphaned registry entries for removed devices." -ForegroundColor Gray
    Write-Host "    They are not needed and will not affect system operation." -ForegroundColor Gray
}

# Cache cleanup
if ($cacheWasCleaned) {
    $hasNonReversible = $true
    Write-Host "`nWINDOWS UPDATE CACHE CLEANED (Regenerates automatically):" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    Write-Host "  Cache size freed: $cacheSize MB" -ForegroundColor Gray
    Write-Host "`n  INFO:" -ForegroundColor White
    Write-Host "    Windows Update cache regenerates automatically." -ForegroundColor Gray
    Write-Host "    No action required." -ForegroundColor Gray
}

if (-not $hasNonReversible) {
    Write-Host "`n  No non-reversible actions were performed." -ForegroundColor Green
}
#endregion

#region COMPLETION
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "RESTORATION COMPLETE" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nSUMMARY:" -ForegroundColor White
Write-Host "  Drivers re-enabled: $($driversDisabled.Count)" -ForegroundColor Cyan
Write-Host "  Services restored: $($servicesOptimized.Count)" -ForegroundColor Cyan
Write-Host "  Non-reversible items reported: $(
    $softwareRemoved.Count + 
    $driversRemoved.Count + 
    $driverStoreCleanup.Count + 
    $ghostRegistryCleaned.Count + 
    $(if ($cacheWasCleaned) { 1 } else { 0 })
)" -ForegroundColor Yellow

Write-Host "`nRECOMMENDED NEXT STEPS:" -ForegroundColor White
Write-Host "  1. Reboot your computer to complete driver restoration" -ForegroundColor Gray
Write-Host "  2. After reboot, check Device Manager for any issues" -ForegroundColor Gray
Write-Host "  3. Run Windows Update to reinstall any missing drivers" -ForegroundColor Gray
Write-Host "  4. Review the non-reversible actions list above" -ForegroundColor Gray

Write-Host "`nLOG FILES:" -ForegroundColor White
Write-Host "  Original log: $logFile" -ForegroundColor Gray
Write-Host "  (Log file preserved for future reference)" -ForegroundColor Gray

Write-Host "`n" + "="*70 -ForegroundColor Green

$reboot = Read-Host "`nReboot now to complete restoration? (Y/N)"
if ($reboot -eq 'Y' -or $reboot -eq 'y') {
    Write-Host "`nRebooting in 10 seconds..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
else {
    Write-Host "`nPlease reboot manually when convenient." -ForegroundColor Yellow
    pause
}
#endregion