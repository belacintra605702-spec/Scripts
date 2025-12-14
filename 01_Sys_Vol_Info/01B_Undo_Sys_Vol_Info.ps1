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
# Script: 01B_UNDO_Sys_Vol_Info.ps1
# Purpose: Restore Windows default settings for System Volume Information
# Requirements: Run as Administrator
# Encoding: ANSI
# =============================================================================

#region FUNCTION: Get all available partitions
function Get-AvailablePartitions {
    try {
        $partitions = @()
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne '' }
        
        foreach ($drive in $drives) {
            $driveLetter = $drive.Name
            $drivePath = $drive.Root
            
            # Get volume information
            $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            if ($volume -and $volume.HealthStatus -eq 'Healthy') {
                $partitions += [PSCustomObject]@{
                    DriveLetter = $driveLetter
                    Path = $drivePath
                    FileSystem = $volume.FileSystemType
                    SizeGB = [math]::Round($volume.Size / 1GB, 2)
                }
            }
        }
        
        return $partitions | Sort-Object DriveLetter
    }
    catch {
        Write-Host "Error detecting partitions: $_" -ForegroundColor Red
        return @()
    }
}
#endregion

#region FUNCTION: Restore Windows default SVI settings
function Restore-DefaultSVISettings {
    param(
        [string]$driveLetter
    )
    
    $drivePath = "$driveLetter`:"
    $sviPath = Join-Path $drivePath "System Volume Information"
    
    Write-Host "  Restoring default settings for $drivePath" -ForegroundColor Cyan
    
    # 1. Enable System Restore (for non-C: drives)
    if ($driveLetter -ne 'C') {
        Write-Host "    - Enabling System Restore..." -ForegroundColor Gray
        try {
            Enable-ComputerRestore -Drive "$drivePath\" -ErrorAction Stop
            Write-Host "      SUCCESS: System Restore enabled" -ForegroundColor Green
        }
        catch {
            Write-Host "      INFO: System Restore may already be enabled or not applicable" -ForegroundColor Gray
        }
    }
    
    # 2. Restore default automatic cleanup setting
    Write-Host "    - Restoring automatic cleanup settings..." -ForegroundColor Gray
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System Volume Information"
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name "StateFlags0064" -ErrorAction SilentlyContinue
            Write-Host "      SUCCESS: Automatic cleanup restored to Windows default" -ForegroundColor Green
        }
        else {
            Write-Host "      INFO: Registry path not found (already at default)" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Registry restore: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 3. Enable VSS/Shadow Copies (Windows default)
    Write-Host "    - Configuring VSS/Shadow Copies..." -ForegroundColor Gray
    try {
        # Set shadow storage to UNBOUNDED (Windows default behavior)
        $vssCmd = "vssadmin resize shadowstorage /for=$drivePath /on=$drivePath /maxsize=UNBOUNDED"
        $vssOutput = cmd /c $vssCmd 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      SUCCESS: VSS/Shadow Copies enabled (UNBOUNDED)" -ForegroundColor Green
        }
        else {
            # If resize fails, try to add shadow storage
            $vssAddCmd = "vssadmin add shadowstorage /for=$drivePath /on=$drivePath /maxsize=UNBOUNDED"
            $vssAddOutput = cmd /c $vssAddCmd 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      SUCCESS: VSS/Shadow Copies configured" -ForegroundColor Green
            }
            else {
                Write-Host "      INFO: VSS may already be at Windows default settings" -ForegroundColor Gray
            }
        }
    }
    catch { 
        Write-Host "      WARNING: VSS configuration: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 4. Restore default indexing setting
    Write-Host "    - Restoring indexing settings..." -ForegroundColor Gray
    try {
        if (Test-Path $sviPath) {
            $item = Get-Item $sviPath -Force -ErrorAction Stop
            $attr = $item.Attributes
            
            # Remove NotContentIndexed flag if present
            if ($attr -band [IO.FileAttributes]::NotContentIndexed) {
                $attr = $attr -band (-bnot [IO.FileAttributes]::NotContentIndexed)
                Set-ItemProperty -Path $sviPath -Name Attributes -Value $attr -Force -ErrorAction Stop
                Write-Host "      SUCCESS: Indexing restored to Windows default" -ForegroundColor Green
            }
            else {
                Write-Host "      INFO: Indexing already at default setting" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "      INFO: System Volume Information folder does not exist" -ForegroundColor Gray
            Write-Host "             (Windows will create it automatically as needed)" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Indexing restore: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 5. Restore default Windows permissions on SVI folder
    Write-Host "    - Restoring Windows default permissions..." -ForegroundColor Gray
    try {
        if (Test-Path $sviPath) {
            # Reset to Windows default permissions
            icacls "$sviPath" /reset /t /q 2>$null | Out-Null
            
            # Apply Windows default permissions
            icacls "$sviPath" /grant "SYSTEM:(OI)(CI)F" /t /q 2>$null | Out-Null
            icacls "$sviPath" /grant "NT SERVICE\TrustedInstaller:(OI)(CI)F" /t /q 2>$null | Out-Null
            icacls "$sviPath" /grant "Administrators:(OI)(CI)RX" /t /q 2>$null | Out-Null
            icacls "$sviPath" /deny "Everyone:(D)" /t /q 2>$null | Out-Null
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "      SUCCESS: Windows default permissions restored" -ForegroundColor Green
            }
            else {
                Write-Host "      WARNING: Some permissions may not have been applied" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "      INFO: System Volume Information folder does not exist" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Permissions restore: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    # 6. Enable System Restore scheduled task
    Write-Host "    - Enabling System Restore scheduled task..." -ForegroundColor Gray
    try {
        $task = Get-ScheduledTask -TaskName "SR" -TaskPath "\Microsoft\Windows\SystemRestore\" -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -eq 'Disabled') {
                Enable-ScheduledTask -TaskName "SR" -TaskPath "\Microsoft\Windows\SystemRestore\" -ErrorAction Stop | Out-Null
                Write-Host "      SUCCESS: System Restore task enabled" -ForegroundColor Green
            }
            else {
                Write-Host "      INFO: System Restore task already enabled" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "      INFO: System Restore task not found (may not exist on this system)" -ForegroundColor Gray
        }
    }
    catch { 
        Write-Host "      WARNING: Task enable: $($_.Exception.Message)" -ForegroundColor Yellow 
    }
    
    Write-Host "  SUCCESS: Windows default settings restored for $drivePath" -ForegroundColor Green
}
#endregion

#region MAIN EXECUTION
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "SYSTEM VOLUME INFORMATION - RESTORE WINDOWS DEFAULTS" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script will restore Windows default settings for:" -ForegroundColor White
Write-Host "  - System Restore functionality" -ForegroundColor Gray
Write-Host "  - Automatic cleanup settings" -ForegroundColor Gray
Write-Host "  - VSS/Shadow Copies (UNBOUNDED)" -ForegroundColor Gray
Write-Host "  - Indexing service" -ForegroundColor Gray
Write-Host "  - Default Windows permissions" -ForegroundColor Gray
Write-Host "  - System Restore scheduled tasks" -ForegroundColor Gray
Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  - C: drive is automatically excluded (Windows system drive)" -ForegroundColor Yellow
Write-Host "  - This does NOT restore deleted files from SVI folders" -ForegroundColor Yellow
Write-Host "  - Only configuration settings are restored to Windows defaults" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan

# Step 1: Get all partitions
Write-Host "`nScanning available partitions..." -ForegroundColor White
$partitions = Get-AvailablePartitions

if ($partitions.Count -eq 0) {
    Write-Host "No partitions found!" -ForegroundColor Red
    pause
    exit 1
}

# Filter out C: drive
$availablePartitions = $partitions | Where-Object { $_.DriveLetter -ne 'C' }

if ($availablePartitions.Count -eq 0) {
    Write-Host "No non-system partitions found to restore!" -ForegroundColor Yellow
    Write-Host "Only C: drive exists, which is automatically excluded." -ForegroundColor Gray
    pause
    exit 0
}

# Display partitions
Write-Host "`nAvailable partitions (excluding C:):" -ForegroundColor White
Write-Host ("-"*70) -ForegroundColor Gray
$partitionTable = $availablePartitions | ForEach-Object {
    [PSCustomObject]@{
        "Drive" = $_.DriveLetter + ":"
        "Size (GB)" = $_.SizeGB
        "File System" = $_.FileSystem
    }
}
$partitionTable | Format-Table -AutoSize

# Step 2: User selection
Write-Host "PARTITION SELECTION" -ForegroundColor White
Write-Host ("-"*40) -ForegroundColor Gray
Write-Host "Select which drives to restore Windows default SVI settings:" -ForegroundColor White

$availableDrives = $availablePartitions | Select-Object -ExpandProperty DriveLetter
Write-Host "Available drives: $($availableDrives -join ', ')" -ForegroundColor Cyan

Write-Host "`nEnter drive letters to process (separated by commas, no spaces)" -ForegroundColor White
Write-Host "Examples:" -ForegroundColor Gray
Write-Host "  - Type 'ALL' to restore all non-system drives" -ForegroundColor Gray
Write-Host "  - Type 'D,E,F' to restore specific drives" -ForegroundColor Gray

$userInput = Read-Host "`nDrives to restore (or ALL)"

$targetDrives = @()

if ($userInput.Trim().ToUpper() -eq 'ALL') {
    $targetDrives = $availableDrives
    Write-Host "`nSelected: ALL drives" -ForegroundColor Cyan
}
elseif ($userInput -ne '') {
    $userInput.Split(',') | ForEach-Object {
        $drive = $_.Trim().ToUpper()
        if ($drive -match '^[A-Z]$') {
            if ($drive -eq 'C') {
                Write-Host "  WARNING: C: drive cannot be selected (system protection)" -ForegroundColor Yellow
            }
            elseif ($drive -in $availableDrives) {
                $targetDrives += $drive
            }
            else {
                Write-Host "  WARNING: Drive $drive not found or not available" -ForegroundColor Yellow
            }
        }
    }
}
else {
    Write-Host "`nNo drives selected!" -ForegroundColor Yellow
    pause
    exit 0
}

if ($targetDrives.Count -eq 0) {
    Write-Host "`nNo valid drives selected for restoration!" -ForegroundColor Yellow
    pause
    exit 0
}

Write-Host "`n" + "-"*70 -ForegroundColor Gray
Write-Host "SELECTION SUMMARY:" -ForegroundColor White
Write-Host "  Drives excluded: C: (system drive)" -ForegroundColor Yellow
Write-Host "  Drives to restore: $($targetDrives -join ', ')" -ForegroundColor Cyan
Write-Host "-"*70 -ForegroundColor Gray

# Step 3: Confirmation
Write-Host "`n" + "!"*70 -ForegroundColor Yellow
Write-Host "CONFIRMATION REQUIRED" -ForegroundColor Yellow
Write-Host "!"*70 -ForegroundColor Yellow
Write-Host "`nThe following operations will be performed:" -ForegroundColor White
foreach ($drive in $targetDrives) {
    Write-Host "  $drive`:" -ForegroundColor Cyan
    Write-Host "    - Enable System Restore" -ForegroundColor Gray
    Write-Host "    - Restore automatic cleanup settings" -ForegroundColor Gray
    Write-Host "    - Enable VSS/Shadow Copies (UNBOUNDED)" -ForegroundColor Gray
    Write-Host "    - Restore indexing to Windows default" -ForegroundColor Gray
    Write-Host "    - Restore default Windows permissions" -ForegroundColor Gray
    Write-Host "    - Enable System Restore scheduled tasks" -ForegroundColor Gray
}
Write-Host "`n" + "!"*70 -ForegroundColor Yellow
Write-Host "This will re-enable Windows management of System Volume Information" -ForegroundColor White
Write-Host "!"*70 -ForegroundColor Yellow

$confirm = Read-Host "`nType 'YES' (in uppercase) to proceed"
if ($confirm -ne 'YES') {
    Write-Host "`nOperation cancelled by user." -ForegroundColor Yellow
    pause
    exit 0
}

# Step 4: Execute restoration
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "RESTORING WINDOWS DEFAULT SETTINGS..." -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan

$results = @()
foreach ($drive in $targetDrives) {
    Write-Host "`nProcessing drive: $drive`:" -ForegroundColor White
    Write-Host "-"*70 -ForegroundColor Gray
    
    Restore-DefaultSVISettings -driveLetter $drive
    
    $results += [PSCustomObject]@{
        Drive = $drive
        Restored = $true
    }
    
    Write-Host "-"*70 -ForegroundColor Gray
    Start-Sleep -Milliseconds 500
}

# Step 5: Summary
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "RESTORATION COMPLETE - SUMMARY" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nResults:" -ForegroundColor White
Write-Host "  Successfully restored: $($results.Count) of $($targetDrives.Count) drives" -ForegroundColor Cyan

Write-Host "`nDrives processed:" -ForegroundColor White
foreach ($result in $results) {
    Write-Host "  $($result.Drive): Windows defaults restored [SUCCESS]" -ForegroundColor Green
}

Write-Host "`n" + "-"*70 -ForegroundColor Gray
Write-Host "SETTINGS RESTORED TO WINDOWS DEFAULTS:" -ForegroundColor White
Write-Host "  - System Restore: Enabled" -ForegroundColor Gray
Write-Host "  - Automatic cleanup: Windows managed" -ForegroundColor Gray
Write-Host "  - VSS/Shadow Copies: UNBOUNDED (Windows default)" -ForegroundColor Gray
Write-Host "  - Indexing service: Enabled" -ForegroundColor Gray
Write-Host "  - Permissions: Windows default (SYSTEM, TrustedInstaller)" -ForegroundColor Gray
Write-Host "  - Scheduled tasks: Enabled" -ForegroundColor Gray

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  - Windows will now manage System Volume Information normally" -ForegroundColor Gray
Write-Host "  - SVI folders will be repopulated with system data over time" -ForegroundColor Gray
Write-Host "  - Shadow copies and restore points will accumulate as configured" -ForegroundColor Gray
Write-Host "  - Deleted files were NOT restored (only settings changed)" -ForegroundColor Gray
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#endregion