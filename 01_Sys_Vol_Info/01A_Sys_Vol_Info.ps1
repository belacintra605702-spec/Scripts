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
# Script: 01A_Sys_Vol_Info.ps1
# Purpose: Clean and disable Windows System Volume Information functions
#          on all partitions except excluded ones
# Requirements: Run as Administrator
# Encoding: ANSI
# =============================================================================

#region INITIAL CHECKS
# =============================================================================
# Check Windows version
$winVersion = [System.Environment]::OSVersion.Version
if ($winVersion.Major -eq 10 -and $winVersion.Build -lt 22000) {
    Write-Host "`nWARNING: This script is designed for Windows 11" -ForegroundColor Yellow
    Write-Host "Detected Windows version: $($winVersion.Major).$($winVersion.Minor).$($winVersion.Build)" -ForegroundColor Yellow
    $confirm = Read-Host "Continue anyway? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') { exit }
}
#endregion

#region FUNCTION: Create System Restore Point
function New-SystemRestorePoint {
    param(
        [string]$description
    )
    
    Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan
    
    try {
        # Enable System Restore on C: if not already enabled
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        
        # Check if System Restore is available
        $restoreEnabled = (Get-ComputerRestorePoint -ErrorAction SilentlyContinue) -ne $null -or 
                          ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "RPSessionInterval" -ErrorAction SilentlyContinue).RPSessionInterval -ne $null)
        
        if (-not $restoreEnabled) {
            Write-Host "  WARNING: System Restore is disabled on this system" -ForegroundColor Yellow
            Write-Host "  Attempting to enable and create restore point..." -ForegroundColor Yellow
            Enable-ComputerRestore -Drive "C:\" -ErrorAction Stop
        }
        
        # Create the restore point
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        
        Write-Host "  SUCCESS: System Restore Point created: $description" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  WARNING: Could not create System Restore Point" -ForegroundColor Yellow
        Write-Host "  Reason: $($_.Exception.Message)" -ForegroundColor Gray
        Write-Host "  The script will continue, but you won't have an automatic restore point." -ForegroundColor Gray
        
        $continue = Read-Host "`n  Continue without restore point? (y/N)"
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            pause
            exit 0
        }
        return $false
    }
}
#endregion

#region FUNCTION: Get all available partitions
function Get-AvailablePartitions {
    try {
        $partitions = @()
        
        # Get all drives with letters
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne '' }
        
        foreach ($drive in $drives) {
            $driveLetter = $drive.Name
            $drivePath = $drive.Root
            
            # Get volume information
            $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            if ($volume) {
                $sizeGB = [math]::Round($volume.Size / 1GB, 2)
                $freeGB = [math]::Round($volume.SizeRemaining / 1GB, 2)
                $fileSystem = $volume.FileSystemType
                $healthStatus = $volume.HealthStatus
                
                # Check if it's a system partition
                $isSystem = $false
                if ($driveLetter -eq 'C') { $isSystem = $true }
                
                $partitions += [PSCustomObject]@{
                    DriveLetter = $driveLetter
                    SizeGB = $sizeGB
                    FreeGB = $freeGB
                    FileSystem = $fileSystem
                    HealthStatus = $healthStatus
                    IsSystem = $isSystem
                    Path = $drivePath
                }
            }
        }
        
        return $partitions
    }
    catch {
        Write-Host "Error detecting partitions: $_" -ForegroundColor Red
        return @()
    }
}
#endregion

#region FUNCTION: Clean System Volume Information folder
function Clean-SystemVolumeInfo {
    param(
        [string]$drivePath
    )
    
    $sviPath = Join-Path $drivePath "System Volume Information"
    
    if (Test-Path $sviPath) {
        Write-Host "  Cleaning: $sviPath" -ForegroundColor Cyan
        
        try {
            # Take ownership and set permissions
            $takeownResult = takeown /f "$sviPath" /r /d y 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "    WARNING: takeown reported issues (this is sometimes normal)" -ForegroundColor Yellow
            }
            
            $icaclsResult = icacls "$sviPath" /grant administrators:F /t 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "    WARNING: icacls reported issues (this is sometimes normal)" -ForegroundColor Yellow
            }
            
            # Remove all contents but keep the folder
            $itemsRemoved = 0
            $itemsFailed = 0
            
            Get-ChildItem -Path $sviPath -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop
                    $itemsRemoved++
                }
                catch {
                    $itemsFailed++
                }
            }
            
            if ($itemsRemoved -gt 0) {
                Write-Host "    SUCCESS: Removed $itemsRemoved items" -ForegroundColor Green
            }
            
            if ($itemsFailed -gt 0) {
                Write-Host "    WARNING: $itemsFailed items could not be removed (may be in use)" -ForegroundColor Yellow
            }
            
            if ($itemsRemoved -eq 0 -and $itemsFailed -eq 0) {
                Write-Host "    INFO: Folder was already empty" -ForegroundColor Gray
            }
            
            return $true
        }
        catch {
            Write-Host "    ERROR: Cleaning failed - $_" -ForegroundColor Red
            return $false
        }
    }
    else {
        Write-Host "  INFO: No System Volume Information folder found" -ForegroundColor Gray
        Write-Host "        (Windows will create it automatically if needed)" -ForegroundColor Gray
        return $true
    }
}
#endregion

#region FUNCTION: Disable all SVI functions
function Disable-SVIFunctions {
    param(
        [string]$driveLetter
    )
    
    $drivePath = "$driveLetter`:"
    $sviPath = Join-Path $drivePath "System Volume Information"
    
    Write-Host "  Disabling SVI functions on $drivePath" -ForegroundColor Cyan
    
    # 1. Disable VSS/Shadow Copies for this volume
    Write-Host "    - Removing VSS/Shadow Copies..." -ForegroundColor Gray
    try {
        $vssOutput = vssadmin delete shadows /for=$drivePath /quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      SUCCESS: VSS/Shadow Copies removed" -ForegroundColor Green
        }
        else {
            Write-Host "      INFO: No shadow copies found or already removed" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: VSS operation: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 2. Disable indexing for System Volume Information
    Write-Host "    - Disabling indexing..." -ForegroundColor Gray
    try {
        if (Test-Path $sviPath) {
            $item = Get-Item $sviPath -Force -ErrorAction Stop
            $attr = $item.Attributes
            $attr = $attr -bor [IO.FileAttributes]::NotContentIndexed
            Set-ItemProperty -Path $sviPath -Name Attributes -Value $attr -Force -ErrorAction Stop
            Write-Host "      SUCCESS: Indexing disabled" -ForegroundColor Green
        }
        else {
            Write-Host "      INFO: SVI folder does not exist yet" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Indexing disable: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 3. Set restrictive permissions on SVI folder
    Write-Host "    - Setting restrictive permissions..." -ForegroundColor Gray
    try {
        if (Test-Path $sviPath) {
            # Remove all permissions except SYSTEM
            icacls "$sviPath" /remove "Authenticated Users" /t 2>$null | Out-Null
            icacls "$sviPath" /remove "Users" /t 2>$null | Out-Null
            icacls "$sviPath" /remove "Administrators" /t 2>$null | Out-Null
            icacls "$sviPath" /grant "SYSTEM:(OI)(CI)F" /t 2>$null | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      SUCCESS: Restrictive permissions set (SYSTEM only)" -ForegroundColor Green
            }
            else {
                Write-Host "      WARNING: Some permission changes may not have applied" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "      INFO: SVI folder does not exist yet" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Permissions set: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 4. Disable System Restore for this volume (if not C:)
    if ($driveLetter -ne 'C') {
        Write-Host "    - Disabling System Restore..." -ForegroundColor Gray
        try {
            Disable-ComputerRestore -Drive "$drivePath\" -ErrorAction Stop
            Write-Host "      SUCCESS: System Restore disabled for $drivePath" -ForegroundColor Green
        }
        catch { 
            Write-Host "      INFO: System Restore was not enabled on this drive" -ForegroundColor Gray
        }
    }
    
    # 5. Disable automatic cleanup via Registry
    Write-Host "    - Configuring registry settings..." -ForegroundColor Gray
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System Volume Information"
        if (Test-Path $regPath) {
            Set-ItemProperty -Path $regPath -Name "StateFlags0064" -Value 0 -Type DWord -Force -ErrorAction Stop
            Write-Host "      SUCCESS: Auto-cleanup disabled" -ForegroundColor Green
        }
        else {
            Write-Host "      INFO: Registry path not found (may not be applicable)" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Registry setting: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    Write-Host "  SUCCESS: All SVI functions processed for $drivePath" -ForegroundColor Green
}
#endregion

#region MAIN EXECUTION
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "SYSTEM VOLUME INFORMATION CLEANER & DISABLER" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script will:" -ForegroundColor White
Write-Host "1. Create a System Restore Point" -ForegroundColor Gray
Write-Host "2. Detect all available partitions" -ForegroundColor Gray
Write-Host "3. Allow you to select partitions to EXCLUDE (C: is always excluded)" -ForegroundColor Gray
Write-Host "4. Clean System Volume Information folders on selected partitions" -ForegroundColor Gray
Write-Host "5. Disable all Windows functions related to SVI on those partitions" -ForegroundColor Gray
Write-Host "`nWARNING: C: drive is ALWAYS excluded to protect Windows 11" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan

# Step 0: Create System Restore Point
$restorePointName = "01A_Sys_Vol_Info - " + (Get-Date -Format "yyyy-MM-dd HH:mm")
$restorePointCreated = New-SystemRestorePoint -description $restorePointName

# Step 1: Get all partitions
Write-Host "`nScanning available partitions..." -ForegroundColor White
$partitions = Get-AvailablePartitions

if ($partitions.Count -eq 0) {
    Write-Host "No partitions found!" -ForegroundColor Red
    pause
    exit 1
}

# Display partitions
Write-Host "`nAvailable partitions:" -ForegroundColor White
Write-Host ("-"*70) -ForegroundColor Gray
$partitionTable = $partitions | ForEach-Object {
    $status = if ($_.IsSystem) { "(SYSTEM)" } else { "" }
    [PSCustomObject]@{
        "Drive" = $_.DriveLetter + ":"
        "Size (GB)" = $_.SizeGB
        "Free (GB)" = $_.FreeGB
        "FS" = $_.FileSystem
        "Status" = $_.HealthStatus
        "Note" = $status
    }
}
$partitionTable | Format-Table -AutoSize

# Step 2: User selection for exclusions
Write-Host "`nPARTITION SELECTION" -ForegroundColor White
Write-Host ("-"*40) -ForegroundColor Gray

# Always exclude C: drive
$excludedDrives = @('C')
Write-Host "C: drive is automatically excluded (Windows 11 system drive)" -ForegroundColor Yellow

# Ask for additional exclusions
Write-Host "`nDo you want to exclude additional drives?" -ForegroundColor White
Write-Host "(e.g., drives with Linux, important backups, or data you want to preserve)" -ForegroundColor Gray
$addExclusions = Read-Host "Add additional exclusions? (y/N)"

if ($addExclusions -eq 'y' -or $addExclusions -eq 'Y') {
    Write-Host "`nEnter drive letters to exclude (separated by commas, no spaces)" -ForegroundColor White
    Write-Host "Example: R,Y or D,E,F" -ForegroundColor Gray
    $userExclusions = Read-Host "Drives to exclude"
    
    if ($userExclusions -ne '') {
        $userExclusions.Split(',') | ForEach-Object {
            $drive = $_.Trim().ToUpper()
            if ($drive -match '^[A-Z]$') {
                if ($drive -ne 'C' -and $drive -notin $excludedDrives) {
                    $excludedDrives += $drive
                }
            }
        }
    }
}

# Determine target drives
$targetDrives = $partitions | Where-Object { 
    $_.DriveLetter -notin $excludedDrives -and $_.HealthStatus -eq 'Healthy'
} | Select-Object -ExpandProperty DriveLetter

Write-Host "`n" + "-"*70 -ForegroundColor Gray
Write-Host "EXCLUSIONS:" -ForegroundColor White
Write-Host "  Drives excluded: $($excludedDrives -join ', ')" -ForegroundColor Yellow
Write-Host "  Drives to process: $(if ($targetDrives.Count -gt 0) { $targetDrives -join ', ' } else { 'NONE' })" -ForegroundColor Cyan
Write-Host "-"*70 -ForegroundColor Gray

if ($targetDrives.Count -eq 0) {
    Write-Host "`nNo drives selected for processing!" -ForegroundColor Yellow
    Write-Host "All available drives have been excluded." -ForegroundColor Gray
    pause
    exit 0
}

# Step 3: Confirmation
Write-Host "`n" + "!"*70 -ForegroundColor Red
Write-Host "CONFIRMATION REQUIRED" -ForegroundColor Red
Write-Host "!"*70 -ForegroundColor Red
Write-Host "`nThe following actions will be performed:" -ForegroundColor White
foreach ($drive in $targetDrives) {
    Write-Host "  $drive`:" -ForegroundColor Yellow
    Write-Host "    - Clean System Volume Information folder (remove all contents)" -ForegroundColor Gray
    Write-Host "    - Delete ALL shadow copies / restore points on this drive" -ForegroundColor Gray
    Write-Host "    - Disable indexing, VSS, and System Restore" -ForegroundColor Gray
    Write-Host "    - Set restrictive permissions (SYSTEM only)" -ForegroundColor Gray
}
Write-Host "`n" + "!"*70 -ForegroundColor Red
Write-Host "WARNING: This operation will DELETE all System Volume Information data" -ForegroundColor Red
Write-Host "         and CANNOT be undone automatically!" -ForegroundColor Red
Write-Host "!"*70 -ForegroundColor Red

$confirm = Read-Host "`nType 'YES' (in uppercase) to proceed"
if ($confirm -ne 'YES') {
    Write-Host "`nOperation cancelled by user." -ForegroundColor Yellow
    pause
    exit 0
}

# Step 4: Execute operations
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "EXECUTING OPERATIONS..." -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan

$results = @()
foreach ($drive in $targetDrives) {
    Write-Host "`nProcessing drive: $drive`:" -ForegroundColor White
    Write-Host "-"*70 -ForegroundColor Gray
    
    # Clean SVI folder
    $cleanResult = Clean-SystemVolumeInfo -drivePath "$drive`:"
    
    # Disable SVI functions
    Disable-SVIFunctions -driveLetter $drive
    
    $results += [PSCustomObject]@{
        Drive = $drive
        Cleaned = $cleanResult
        FunctionsDisabled = $true
    }
    
    Write-Host "-"*70 -ForegroundColor Gray
    Start-Sleep -Milliseconds 500
}

# Step 5: Summary
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "OPERATION COMPLETE - SUMMARY" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

$successCount = ($results | Where-Object { $_.Cleaned -eq $true }).Count
Write-Host "`nResults:" -ForegroundColor White
Write-Host "  Successfully processed: $successCount of $($targetDrives.Count) drives" -ForegroundColor Cyan

Write-Host "`nDetailed results:" -ForegroundColor White
foreach ($result in $results) {
    $cleanStatus = if ($result.Cleaned) { "SUCCESS" } else { "PARTIAL" }
    $cleanColor = if ($result.Cleaned) { "Green" } else { "Yellow" }
    Write-Host "  $($result.Drive): Cleaned [$cleanStatus] | Functions Disabled [SUCCESS]" -ForegroundColor $cleanColor
}

Write-Host "`n" + "-"*70 -ForegroundColor Gray
Write-Host "WHAT WAS DONE:" -ForegroundColor White
Write-Host "  - System Volume Information folders cleaned (contents removed)" -ForegroundColor Gray
Write-Host "  - VSS/Shadow copies deleted from processed drives" -ForegroundColor Gray
Write-Host "  - Indexing disabled on SVI folders" -ForegroundColor Gray
Write-Host "  - System Restore disabled on non-system drives" -ForegroundColor Gray
Write-Host "  - Restrictive permissions set (SYSTEM only)" -ForegroundColor Gray

if ($restorePointCreated) {
    Write-Host "`n  System Restore Point: $restorePointName" -ForegroundColor Cyan
}

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  - Windows may recreate System Volume Information folders as needed" -ForegroundColor Gray
Write-Host "  - Some system services may restore default settings over time" -ForegroundColor Gray
Write-Host "  - Use the UNDO script to restore Windows default settings" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#endregion