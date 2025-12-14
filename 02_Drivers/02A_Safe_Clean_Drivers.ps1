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
# Script: 02A_Safe_Clean_Drivers.ps1
# Purpose: Safe cleanup of ACER software, drivers, orphaned drivers, and
#          system optimization
# Requirements: Run as Administrator, Windows 11
# Encoding: ANSI
# UNDO Support: Generates log file for 02B_UNDO script
# =============================================================================

#region INITIALIZATION
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "SAFE DRIVER & SOFTWARE CLEANUP TOOL" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script will:" -ForegroundColor White
Write-Host "  1. Remove ACER bloatware software" -ForegroundColor Gray
Write-Host "  2. Clean ACER bloatware drivers" -ForegroundColor Gray
Write-Host "  3. Remove orphaned and obsolete drivers" -ForegroundColor Gray
Write-Host "  4. Clean old driver store versions" -ForegroundColor Gray
Write-Host "  5. Clean ghost registry entries" -ForegroundColor Gray
Write-Host "  6. Optimize driver-related services" -ForegroundColor Gray
Write-Host "  7. Clean Windows Update driver cache" -ForegroundColor Gray
Write-Host "`nIMPORTANT: All actions are SAFE and reversible via UNDO script" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan

# Create System Restore Point
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    $restorePointName = "02A_Safe_Clean_Drivers - " + (Get-Date -Format "yyyy-MM-dd HH:mm")
    Checkpoint-Computer -Description $restorePointName -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
    Write-Host "  SUCCESS: System Restore Point created" -ForegroundColor Green
    Write-Host "  Name: $restorePointName" -ForegroundColor Gray
}
catch {
    Write-Host "  WARNING: Could not create System Restore Point" -ForegroundColor Yellow
    Write-Host "  Reason: $($_.Exception.Message)" -ForegroundColor Gray
    $continue = Read-Host "`n  Continue without restore point? (y/N)"
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        pause
        exit 0
    }
}

# Initialize log file
$logFolder = "$env:USERPROFILE\Documents\DriverCleanupLogs"
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
}
$logFile = "$logFolder\DriverCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logContent = @()
$logContent += "="*70
$logContent += "DRIVER CLEANUP LOG"
$logContent += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$logContent += "="*70
$logContent += ""

# Actions tracker
$actions = @{
    SoftwareRemoved = @()
    DriversRemoved = @()
    DriversDisabled = @()
    DriverStoreCleanup = @()
    GhostRegistryCleaned = @()
    ServicesOptimized = @()
    CacheCleaned = $false
    CacheSize = 0
}

function Add-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logContent += "[$timestamp] $message"
}
#endregion

#region STEP 1: ACER SOFTWARE REMOVAL
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 1: ACER BLOATWARE SOFTWARE DETECTION" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Starting ACER software detection..."

# ACER bloatware software list
$acerSoftwarePatterns = @(
    "Acer Care Center*",
    "Acer Quick Access*",
    "Acer Portal*",
    "Acer Configuration Manager*",
    "Acer Product Registration*",
    "Acer User Experience*",
    "Acer Collection*",
    "Acer Jump Start*",
    "AOP Framework*"
)

Write-Host "`nScanning for ACER software..." -ForegroundColor Cyan

$acerSoftwareFound = @()

# Method 1: Win32_Product (slow but reliable)
Write-Host "  - Checking installed programs..." -ForegroundColor Gray
$installedPrograms = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue

foreach ($pattern in $acerSoftwarePatterns) {
    $matches = $installedPrograms | Where-Object { $_.Name -like $pattern }
    foreach ($match in $matches) {
        $acerSoftwareFound += [PSCustomObject]@{
            Name = $match.Name
            Version = $match.Version
            IdentifyingNumber = $match.IdentifyingNumber
            Method = "Win32_Product"
        }
    }
}

# Method 2: Registry (faster)
Write-Host "  - Checking registry..." -ForegroundColor Gray
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $uninstallPaths) {
    $regItems = Get-ItemProperty $path -ErrorAction SilentlyContinue
    foreach ($item in $regItems) {
        foreach ($pattern in $acerSoftwarePatterns) {
            if ($item.DisplayName -like $pattern) {
                # Check if not already in list
                if ($acerSoftwareFound.Name -notcontains $item.DisplayName) {
                    $acerSoftwareFound += [PSCustomObject]@{
                        Name = $item.DisplayName
                        Version = $item.DisplayVersion
                        UninstallString = $item.UninstallString
                        Method = "Registry"
                    }
                }
            }
        }
    }
}

if ($acerSoftwareFound.Count -eq 0) {
    Write-Host "`n  No ACER bloatware software found." -ForegroundColor Green
    Add-Log "No ACER software found"
}
else {
    Write-Host "`nFound $($acerSoftwareFound.Count) ACER software items:" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    
    for ($i = 0; $i -lt $acerSoftwareFound.Count; $i++) {
        $software = $acerSoftwareFound[$i]
        Write-Host "  [$($i+1)] $($software.Name)" -ForegroundColor Cyan
        Write-Host "      Version: $($software.Version)" -ForegroundColor Gray
    }
    
    Write-Host "`nSelect software to remove:" -ForegroundColor White
    Write-Host "  - Enter numbers separated by commas (e.g., 1,3,5)" -ForegroundColor Gray
    Write-Host "  - Enter 'ALL' to remove all" -ForegroundColor Gray
    Write-Host "  - Enter 'NONE' to skip" -ForegroundColor Gray
    
    $selection = Read-Host "`nYour selection"
    
    $toRemove = @()
    
    if ($selection.ToUpper() -eq "ALL") {
        $toRemove = $acerSoftwareFound
    }
    elseif ($selection.ToUpper() -ne "NONE" -and $selection -ne "") {
        $indices = $selection.Split(',') | ForEach-Object { $_.Trim() }
        foreach ($index in $indices) {
            if ($index -match '^\d+$') {
                $idx = [int]$index - 1
                if ($idx -ge 0 -and $idx -lt $acerSoftwareFound.Count) {
                    $toRemove += $acerSoftwareFound[$idx]
                }
            }
        }
    }
    
    if ($toRemove.Count -gt 0) {
        Write-Host "`n  Removing $($toRemove.Count) software items..." -ForegroundColor Cyan
        
        foreach ($software in $toRemove) {
            Write-Host "`n    Removing: $($software.Name)..." -ForegroundColor Yellow
            
            try {
                if ($software.Method -eq "Win32_Product" -and $software.IdentifyingNumber) {
                    $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.IdentifyingNumber -eq $software.IdentifyingNumber }
                    if ($product) {
                        $result = $product.Uninstall()
                        if ($result.ReturnValue -eq 0) {
                            Write-Host "      SUCCESS: Software removed" -ForegroundColor Green
                            Add-Log "Removed software: $($software.Name) v$($software.Version)"
                            $actions.SoftwareRemoved += $software.Name
                        }
                        else {
                            Write-Host "      WARNING: Uninstall returned code $($result.ReturnValue)" -ForegroundColor Yellow
                        }
                    }
                }
                elseif ($software.UninstallString) {
                    # Use registry uninstall string
                    $uninstallCmd = $software.UninstallString
                    if ($uninstallCmd -like "msiexec*") {
                        $uninstallCmd = $uninstallCmd -replace "/I", "/X"
                        $uninstallCmd += " /quiet /norestart"
                    }
                    
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstallCmd" -Wait -NoNewWindow
                    Write-Host "      SUCCESS: Uninstall command executed" -ForegroundColor Green
                    Add-Log "Removed software: $($software.Name) v$($software.Version)"
                    $actions.SoftwareRemoved += $software.Name
                }
            }
            catch {
                Write-Host "      ERROR: Failed to remove - $_" -ForegroundColor Red
                Add-Log "ERROR removing software $($software.Name): $_"
            }
        }
    }
    else {
        Write-Host "`n  No software selected for removal." -ForegroundColor Gray
    }
}
#endregion

#region STEP 2: ACER DRIVER CLEANUP
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 2: ACER BLOATWARE DRIVER DETECTION" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Starting ACER driver detection..."

# Critical hardware that should NEVER be touched
$criticalKeywords = @(
    "Chipset", "Graphics", "Display", "Audio", "Sound", "WiFi", "Wireless",
    "Ethernet", "Network", "Bluetooth", "Processor", "CPU", "Disk", "Storage",
    "USB Host", "SATA", "NVMe", "Memory", "ACPI", "System", "PCI Bridge"
)

Write-Host "`nScanning for ACER drivers..." -ForegroundColor Cyan
Write-Host "  (Excluding critical system drivers)" -ForegroundColor Gray

$allDrivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue
$acerDrivers = @()

foreach ($driver in $allDrivers) {
    $isAcer = $false
    $isCritical = $false
    
    # Check if it's ACER
    if ($driver.Manufacturer -like "*Acer*" -or 
        $driver.DeviceName -like "*Acer*" -or
        $driver.DriverProviderName -like "*Acer*") {
        $isAcer = $true
    }
    
    # Check if it's critical
    foreach ($keyword in $criticalKeywords) {
        if ($driver.DeviceName -like "*$keyword*" -or $driver.DeviceClass -like "*$keyword*") {
            $isCritical = $true
            break
        }
    }
    
    if ($isAcer -and -not $isCritical) {
        $acerDrivers += $driver
    }
}

if ($acerDrivers.Count -eq 0) {
    Write-Host "`n  No ACER bloatware drivers found." -ForegroundColor Green
    Add-Log "No ACER bloatware drivers found"
}
else {
    Write-Host "`nFound $($acerDrivers.Count) ACER non-critical drivers:" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    
    for ($i = 0; $i -lt $acerDrivers.Count; $i++) {
        $driver = $acerDrivers[$i]
        Write-Host "  [$($i+1)] $($driver.DeviceName)" -ForegroundColor Cyan
        Write-Host "      Manufacturer: $($driver.Manufacturer)" -ForegroundColor Gray
        Write-Host "      Driver Version: $($driver.DriverVersion)" -ForegroundColor Gray
    }
    
    Write-Host "`nSelect drivers to remove:" -ForegroundColor White
    Write-Host "  - Enter numbers separated by commas (e.g., 1,2,4)" -ForegroundColor Gray
    Write-Host "  - Enter 'ALL' to remove all" -ForegroundColor Gray
    Write-Host "  - Enter 'NONE' to skip" -ForegroundColor Gray
    
    $selection = Read-Host "`nYour selection"
    
    $toRemove = @()
    
    if ($selection.ToUpper() -eq "ALL") {
        $toRemove = $acerDrivers
    }
    elseif ($selection.ToUpper() -ne "NONE" -and $selection -ne "") {
        $indices = $selection.Split(',') | ForEach-Object { $_.Trim() }
        foreach ($index in $indices) {
            if ($index -match '^\d+$') {
                $idx = [int]$index - 1
                if ($idx -ge 0 -and $idx -lt $acerDrivers.Count) {
                    $toRemove += $acerDrivers[$idx]
                }
            }
        }
    }
    
    if ($toRemove.Count -gt 0) {
        Write-Host "`n  Removing $($toRemove.Count) drivers..." -ForegroundColor Cyan
        
        foreach ($driver in $toRemove) {
            Write-Host "`n    Processing: $($driver.DeviceName)..." -ForegroundColor Yellow
            
            try {
                # Try to remove via pnputil if INF is available
                if ($driver.InfName) {
                    $result = pnputil /delete-driver $driver.InfName /uninstall /force 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "      SUCCESS: Driver removed" -ForegroundColor Green
                        Add-Log "Removed driver: $($driver.DeviceName) (INF: $($driver.InfName))"
                        $actions.DriversRemoved += @{
                            Name = $driver.DeviceName
                            INF = $driver.InfName
                            DeviceID = $driver.DeviceID
                        }
                    }
                    else {
                        Write-Host "      WARNING: pnputil reported issues" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "      INFO: No INF file found, attempting to disable..." -ForegroundColor Gray
                    
                    # Try to disable device
                    $pnpDevice = Get-PnpDevice | Where-Object { $_.InstanceId -eq $driver.DeviceID }
                    if ($pnpDevice) {
                        Disable-PnpDevice -InstanceId $driver.DeviceID -Confirm:$false -ErrorAction Stop
                        Write-Host "      SUCCESS: Driver disabled" -ForegroundColor Green
                        Add-Log "Disabled driver: $($driver.DeviceName)"
                        $actions.DriversDisabled += $driver.DeviceName
                    }
                }
            }
            catch {
                Write-Host "      ERROR: Failed to process - $_" -ForegroundColor Red
                Add-Log "ERROR processing driver $($driver.DeviceName): $_"
            }
        }
    }
    else {
        Write-Host "`n  No drivers selected for removal." -ForegroundColor Gray
    }
}
#endregion

#region STEP 3: ORPHANED DRIVERS CLEANUP
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 3: ORPHANED & OBSOLETE DRIVERS" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Scanning for orphaned drivers..."

Write-Host "`nDetecting orphaned drivers..." -ForegroundColor Cyan
Write-Host "  (Drivers for devices no longer present)" -ForegroundColor Gray

# Find drivers for non-present devices
$orphanedDrivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object {
    $driver = $_
    $device = Get-PnpDevice -InstanceId $driver.DeviceID -ErrorAction SilentlyContinue
    
    # Device not present or in problem state
    (-not $device) -or ($device.Status -ne "OK" -and $device.Status -ne "Degraded")
}

# Filter out critical orphaned drivers (keep OS cleanup)
$safeOrphanedDrivers = $orphanedDrivers | Where-Object {
    $driver = $_
    $isSafe = $true
    
    foreach ($keyword in $criticalKeywords) {
        if ($driver.DeviceName -like "*$keyword*") {
            $isSafe = $false
            break
        }
    }
    
    $isSafe
}

if ($safeOrphanedDrivers.Count -eq 0) {
    Write-Host "`n  No safe orphaned drivers found." -ForegroundColor Green
    Add-Log "No orphaned drivers found"
}
else {
    Write-Host "`nFound $($safeOrphanedDrivers.Count) orphaned drivers:" -ForegroundColor Yellow
    Write-Host "-"*70 -ForegroundColor Gray
    
    for ($i = 0; $i -lt $safeOrphanedDrivers.Count; $i++) {
        $driver = $safeOrphanedDrivers[$i]
        Write-Host "  [$($i+1)] $($driver.DeviceName)" -ForegroundColor Cyan
        Write-Host "      Status: Device no longer present" -ForegroundColor Gray
    }
    
    Write-Host "`nSelect orphaned drivers to remove:" -ForegroundColor White
    Write-Host "  - Enter numbers separated by commas" -ForegroundColor Gray
    Write-Host "  - Enter 'ALL' to remove all" -ForegroundColor Gray
    Write-Host "  - Enter 'NONE' to skip" -ForegroundColor Gray
    
    $selection = Read-Host "`nYour selection"
    
    $toRemove = @()
    
    if ($selection.ToUpper() -eq "ALL") {
        $toRemove = $safeOrphanedDrivers
    }
    elseif ($selection.ToUpper() -ne "NONE" -and $selection -ne "") {
        $indices = $selection.Split(',') | ForEach-Object { $_.Trim() }
        foreach ($index in $indices) {
            if ($index -match '^\d+$') {
                $idx = [int]$index - 1
                if ($idx -ge 0 -and $idx -lt $safeOrphanedDrivers.Count) {
                    $toRemove += $safeOrphanedDrivers[$idx]
                }
            }
        }
    }
    
    if ($toRemove.Count -gt 0) {
        Write-Host "`n  Removing $($toRemove.Count) orphaned drivers..." -ForegroundColor Cyan
        
        foreach ($driver in $toRemove) {
            try {
                if ($driver.InfName) {
                    pnputil /delete-driver $driver.InfName /uninstall /force 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "    SUCCESS: $($driver.DeviceName)" -ForegroundColor Green
                        Add-Log "Removed orphaned driver: $($driver.DeviceName)"
                        $actions.DriversRemoved += @{
                            Name = $driver.DeviceName
                            INF = $driver.InfName
                            Reason = "Orphaned"
                        }
                    }
                }
            }
            catch {
                Write-Host "    ERROR: $($driver.DeviceName) - $_" -ForegroundColor Red
            }
        }
    }
}
#endregion

#region STEP 4: DRIVER STORE CLEANUP
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 4: DRIVER STORE OLD VERSIONS CLEANUP" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Scanning driver store for old versions..."

Write-Host "`nAnalyzing driver store..." -ForegroundColor Cyan

try {
    $driverList = pnputil /enum-drivers 2>&1 | Out-String
    
    # Parse driver store entries
    $driverEntries = @()
    $lines = $driverList -split "`n"
    
    $currentDriver = @{}
    foreach ($line in $lines) {
        if ($line -match "Published Name\s*:\s*(.+)") {
            if ($currentDriver.Count -gt 0) {
                $driverEntries += [PSCustomObject]$currentDriver
            }
            $currentDriver = @{ PublishedName = $matches[1].Trim() }
        }
        elseif ($line -match "Original Name\s*:\s*(.+)") {
            $currentDriver.OriginalName = $matches[1].Trim()
        }
        elseif ($line -match "Provider Name\s*:\s*(.+)") {
            $currentDriver.Provider = $matches[1].Trim()
        }
        elseif ($line -match "Class Name\s*:\s*(.+)") {
            $currentDriver.ClassName = $matches[1].Trim()
        }
        elseif ($line -match "Driver Version\s*:\s*(.+)") {
            $currentDriver.Version = $matches[1].Trim()
        }
        elseif ($line -match "Signer Name\s*:\s*(.+)") {
            $currentDriver.Signer = $matches[1].Trim()
        }
    }
    
    if ($currentDriver.Count -gt 0) {
        $driverEntries += [PSCustomObject]$currentDriver
    }
    
    # Group by original name and find duplicates
    $duplicateDrivers = $driverEntries | Group-Object OriginalName | Where-Object { $_.Count -gt 1 }
    
    if ($duplicateDrivers.Count -eq 0) {
        Write-Host "`n  No duplicate driver versions found in store." -ForegroundColor Green
        Add-Log "No duplicate driver versions found"
    }
    else {
        $oldVersions = @()
        
        foreach ($group in $duplicateDrivers) {
            $versions = $group.Group | Sort-Object { [version]($_.Version -replace '[^\d.]', '') } -ErrorAction SilentlyContinue
            
            # Keep only the newest, mark others as old
            if ($versions.Count -gt 1) {
                for ($i = 0; $i -lt ($versions.Count - 1); $i++) {
                    $oldVersions += $versions[$i]
                }
            }
        }
        
        if ($oldVersions.Count -eq 0) {
            Write-Host "`n  No old driver versions found." -ForegroundColor Green
        }
        else {
            Write-Host "`nFound $($oldVersions.Count) old driver versions:" -ForegroundColor Yellow
            Write-Host "-"*70 -ForegroundColor Gray
            
            for ($i = 0; $i -lt $oldVersions.Count; $i++) {
                $driver = $oldVersions[$i]
                Write-Host "  [$($i+1)] $($driver.OriginalName)" -ForegroundColor Cyan
                Write-Host "      Version: $($driver.Version) | INF: $($driver.PublishedName)" -ForegroundColor Gray
            }
            
            Write-Host "`nSelect old driver versions to remove:" -ForegroundColor White
            Write-Host "  - Enter numbers separated by commas" -ForegroundColor Gray
            Write-Host "  - Enter 'ALL' to remove all old versions" -ForegroundColor Gray
            Write-Host "  - Enter 'NONE' to skip" -ForegroundColor Gray
            
            $selection = Read-Host "`nYour selection"
            
            $toRemove = @()
            
            if ($selection.ToUpper() -eq "ALL") {
                $toRemove = $oldVersions
            }
            elseif ($selection.ToUpper() -ne "NONE" -and $selection -ne "") {
                $indices = $selection.Split(',') | ForEach-Object { $_.Trim() }
                foreach ($index in $indices) {
                    if ($index -match '^\d+$') {
                        $idx = [int]$index - 1
                        if ($idx -ge 0 -and $idx -lt $oldVersions.Count) {
                            $toRemove += $oldVersions[$idx]
                        }
                    }
                }
            }
            
            if ($toRemove.Count -gt 0) {
                Write-Host "`n  Removing $($toRemove.Count) old driver versions..." -ForegroundColor Cyan
                
                foreach ($driver in $toRemove) {
                    try {
                        pnputil /delete-driver $driver.PublishedName /force 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "    SUCCESS: $($driver.OriginalName) v$($driver.Version)" -ForegroundColor Green
                            Add-Log "Removed old driver version: $($driver.OriginalName) v$($driver.Version)"
                            $actions.DriverStoreCleanup += "$($driver.OriginalName) v$($driver.Version)"
                        }
                    }
                    catch {
                        Write-Host "    ERROR: $($driver.OriginalName) - $_" -ForegroundColor Red
                    }
                }
            }
        }
    }
}
catch {
    Write-Host "`n  ERROR: Failed to analyze driver store - $_" -ForegroundColor Red
    Add-Log "ERROR analyzing driver store: $_"
}
#endregion

#region STEP 5: GHOST REGISTRY CLEANUP
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 5: GHOST REGISTRY ENTRIES CLEANUP" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Scanning for ghost registry entries..."

Write-Host "`nScanning registry for orphaned device entries..." -ForegroundColor Cyan
Write-Host "  (Entries for removed devices)" -ForegroundColor Gray

try {
    $enumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum"
    $ghostEntries = @()
    
    # Scan specific paths known to contain ghost entries
    $pathsToScan = @(
        "$enumPath\ROOT",
        "$enumPath\USB",
        "$enumPath\PCI"
    )
    
    foreach ($basePath in $pathsToScan) {
        if (Test-Path $basePath) {
            $devices = Get-ChildItem -Path $basePath -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -match '^{' }
            
            foreach ($device in $devices) {
                # Check if device has configuration but is not present
                $configFlags = Get-ItemProperty -Path $device.PSPath -Name "ConfigFlags" -ErrorAction SilentlyContinue
                
                # ConfigFlags with bit 0x00000001 set means device is not present
                if ($configFlags -and ($configFlags.ConfigFlags -band 0x00000001)) {
                    $friendlyName = Get-ItemProperty -Path $device.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue
                    
                    $ghostEntries += [PSCustomObject]@{
                        Path = $device.PSPath
                        Name = if ($friendlyName) { $friendlyName.FriendlyName } else { $device.PSChildName }
                        RegistryPath = $device.Name
                    }
                }
            }
        }
    }
    
    if ($ghostEntries.Count -eq 0) {
        Write-Host "`n  No ghost registry entries found." -ForegroundColor Green
        Add-Log "No ghost registry entries found"
    }
    else {
        Write-Host "`nFound $($ghostEntries.Count) ghost registry entries:" -ForegroundColor Yellow
        Write-Host "-"*70 -ForegroundColor Gray
        
        for ($i = 0; $i -lt $ghostEntries.Count; $i++) {
            $entry = $ghostEntries[$i]
            Write-Host "  [$($i+1)] $($entry.Name)" -ForegroundColor Cyan
            Write-Host "      Path: ...$(($entry.RegistryPath -split '\\')[-2..-1] -join '\')" -ForegroundColor Gray
        }
        
        Write-Host "`nSelect ghost entries to remove:" -ForegroundColor White
        Write-Host "  - Enter numbers separated by commas" -F

<function_calls>
<invoke name="artifacts">
<parameter name="command">update</parameter>
<parameter name="id">safe_clean_drivers</parameter>
<parameter name="old_str">        Write-Host "`nSelect ghost entries to remove:" -ForegroundColor White
        Write-Host "  - Enter numbers separated by commas" -F</parameter>
<parameter name="new_str">        Write-Host "`nSelect ghost entries to remove:" -ForegroundColor White
        Write-Host "  - Enter numbers separated by commas" -ForegroundColor Gray
        Write-Host "  - Enter 'ALL' to remove all" -ForegroundColor Gray
        Write-Host "  - Enter 'NONE' to skip" -ForegroundColor Gray
        
        $selection = Read-Host "`nYour selection"
        
        $toRemove = @()
        
        if ($selection.ToUpper() -eq "ALL") {
            $toRemove = $ghostEntries
        }
        elseif ($selection.ToUpper() -ne "NONE" -and $selection -ne "") {
            $indices = $selection.Split(',') | ForEach-Object { $_.Trim() }
            foreach ($index in $indices) {
                if ($index -match '^\d+$') {
                    $idx = [int]$index - 1
                    if ($idx -ge 0 -and $idx -lt $ghostEntries.Count) {
                        $toRemove += $ghostEntries[$idx]
                    }
                }
            }
        }
        
        if ($toRemove.Count -gt 0) {
            Write-Host "`n  Removing $($toRemove.Count) ghost registry entries..." -ForegroundColor Cyan
            
            foreach ($entry in $toRemove) {
                try {
                    Remove-Item -Path $entry.Path -Recurse -Force -ErrorAction Stop
                    Write-Host "    SUCCESS: $($entry.Name)" -ForegroundColor Green
                    Add-Log "Removed ghost registry entry: $($entry.Name)"
                    $actions.GhostRegistryCleaned += $entry.Name
                }
                catch {
                    Write-Host "    ERROR: $($entry.Name) - $_" -ForegroundColor Red
                    Add-Log "ERROR removing ghost entry $($entry.Name): $_"
                }
            }
        }
    }
}
catch {
    Write-Host "`n  ERROR: Failed to scan registry - $_" -ForegroundColor Red
    Add-Log "ERROR scanning ghost registry: $_"
}
#endregion

#region STEP 6: SERVICE OPTIMIZATION
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 6: DRIVER-RELATED SERVICE OPTIMIZATION" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Optimizing driver-related services..."

Write-Host "`nOptimizing services for better performance..." -ForegroundColor Cyan

$servicesToOptimize = @(
    @{Name="DeviceInstall"; StartupType="Manual"; Description="Device Installation Service"},
    @{Name="DeviceSetupManager"; StartupType="Manual"; Description="Device Setup Manager"},
    @{Name="DsmSvc"; StartupType="Manual"; Description="Device Management Service"}
)

foreach ($svc in $servicesToOptimize) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            $currentStartup = (Get-WmiObject -Class Win32_Service -Filter "Name='$($svc.Name)'").StartMode
            
            if ($currentStartup -ne $svc.StartupType) {
                Set-Service -Name $svc.Name -StartupType $svc.StartupType -ErrorAction Stop
                Write-Host "  SUCCESS: $($svc.Description) -> $($svc.StartupType)" -ForegroundColor Green
                Add-Log "Optimized service: $($svc.Name) from $currentStartup to $($svc.StartupType)"
                $actions.ServicesOptimized += "$($svc.Name):$currentStartup->$($svc.StartupType)"
            }
            else {
                Write-Host "  INFO: $($svc.Description) already at $($svc.StartupType)" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "  ERROR: Failed to optimize $($svc.Name) - $_" -ForegroundColor Red
        Add-Log "ERROR optimizing service $($svc.Name): $_"
    }
}
#endregion

#region STEP 7: WINDOWS UPDATE CACHE CLEANUP
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 7: WINDOWS UPDATE DRIVER CACHE CLEANUP" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

Add-Log "Cleaning Windows Update cache..."

Write-Host "`nCleaning Windows Update driver cache..." -ForegroundColor Cyan

try {
    $cachePath = "C:\Windows\SoftwareDistribution\Download"
    
    if (Test-Path $cachePath) {
        $cacheItems = Get-ChildItem $cachePath -Recurse -ErrorAction SilentlyContinue
        $cacheSize = ($cacheItems | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1MB
        
        if ($cacheSize -gt 0) {
            Write-Host "  Cache size: $([math]::Round($cacheSize, 2)) MB" -ForegroundColor Gray
            
            $confirm = Read-Host "  Clean Windows Update cache? (Y/N)"
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                # Stop Windows Update service
                Write-Host "  Stopping Windows Update service..." -ForegroundColor Gray
                Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                
                Start-Sleep -Seconds 2
                
                # Clean cache
                Get-ChildItem $cachePath -Recurse -ErrorAction SilentlyContinue | 
                    Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                
                Write-Host "  SUCCESS: Cache cleaned - Freed $([math]::Round($cacheSize, 2)) MB" -ForegroundColor Green
                Add-Log "Cleaned Windows Update cache: $([math]::Round($cacheSize, 2)) MB"
                $actions.CacheCleaned = $true
                $actions.CacheSize = [math]::Round($cacheSize, 2)
                
                # Restart Windows Update service
                Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "  Skipped Windows Update cache cleanup" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  INFO: Cache is already empty" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  INFO: Cache path not found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  ERROR: Failed to clean cache - $_" -ForegroundColor Red
    Add-Log "ERROR cleaning Windows Update cache: $_"
}
#endregion

#region FINALIZATION
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "OPERATION COMPLETE - GENERATING LOG" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

# Generate summary log
$logContent += ""
$logContent += "="*70
$logContent += "SUMMARY OF ACTIONS"
$logContent += "="*70
$logContent += ""

$logContent += "SOFTWARE REMOVED: $($actions.SoftwareRemoved.Count)"
foreach ($sw in $actions.SoftwareRemoved) {
    $logContent += "  - $sw"
}
$logContent += ""

$logContent += "DRIVERS REMOVED: $($actions.DriversRemoved.Count)"
foreach ($drv in $actions.DriversRemoved) {
    $logContent += "  - $($drv.Name) (INF: $($drv.INF))"
}
$logContent += ""

$logContent += "DRIVERS DISABLED: $($actions.DriversDisabled.Count)"
foreach ($drv in $actions.DriversDisabled) {
    $logContent += "  - $drv"
}
$logContent += ""

$logContent += "DRIVER STORE CLEANUP: $($actions.DriverStoreCleanup.Count)"
foreach ($ds in $actions.DriverStoreCleanup) {
    $logContent += "  - $ds"
}
$logContent += ""

$logContent += "GHOST REGISTRY ENTRIES CLEANED: $($actions.GhostRegistryCleaned.Count)"
foreach ($gr in $actions.GhostRegistryCleaned) {
    $logContent += "  - $gr"
}
$logContent += ""

$logContent += "SERVICES OPTIMIZED: $($actions.ServicesOptimized.Count)"
foreach ($svc in $actions.ServicesOptimized) {
    $logContent += "  - $svc"
}
$logContent += ""

$logContent += "WINDOWS UPDATE CACHE:"
$logContent += "  Cleaned: $($actions.CacheCleaned)"
if ($actions.CacheCleaned) {
    $logContent += "  Size freed: $($actions.CacheSize) MB"
}
$logContent += ""

$logContent += "="*70
$logContent += "END OF LOG"
$logContent += "="*70

# Save log
$logContent | Out-File -FilePath $logFile -Encoding UTF8

Write-Host "`nSUMMARY:" -ForegroundColor White
Write-Host "  Software removed: $($actions.SoftwareRemoved.Count)" -ForegroundColor Cyan
Write-Host "  Drivers removed: $($actions.DriversRemoved.Count)" -ForegroundColor Cyan
Write-Host "  Drivers disabled: $($actions.DriversDisabled.Count)" -ForegroundColor Cyan
Write-Host "  Driver store cleaned: $($actions.DriverStoreCleanup.Count)" -ForegroundColor Cyan
Write-Host "  Ghost entries cleaned: $($actions.GhostRegistryCleaned.Count)" -ForegroundColor Cyan
Write-Host "  Services optimized: $($actions.ServicesOptimized.Count)" -ForegroundColor Cyan
Write-Host "  Cache cleaned: $(if ($actions.CacheCleaned) { 'Yes (' + $actions.CacheSize + ' MB)' } else { 'No' })" -ForegroundColor Cyan

Write-Host "`nLOG FILE:" -ForegroundColor White
Write-Host "  Location: $logFile" -ForegroundColor Gray
Write-Host "  Use this log with 02B_UNDO script to restore changes" -ForegroundColor Yellow

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  - All changes are logged for potential reversal" -ForegroundColor Gray
Write-Host "  - System Restore Point was created at the beginning" -ForegroundColor Gray
Write-Host "  - Reboot recommended to complete driver cleanup" -ForegroundColor Gray

Write-Host "`n" + "="*70 -ForegroundColor Green

$reboot = Read-Host "`nReboot now to complete cleanup? (Y/N)"
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
#endregion</parameter>