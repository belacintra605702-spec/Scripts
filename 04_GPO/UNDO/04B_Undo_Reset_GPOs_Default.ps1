# =============================================================================
# Script: 04B_Undo_Reset_GPOs_Default.ps1
# Purpose: Restore registry-based GPO settings to their original state
#          before running 04A_Reset_GPOs_Default.ps1
# Requirements: Run as Administrator, Windows 11
# Encoding: ANSI
# Location: Can be run from any location (auto-detects backup folders)
# =============================================================================

#region ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION
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

Write-Host "`nRunning with administrative privileges..." -ForegroundColor Green
# =============================================================================
#endregion

#region INITIALIZATION AND BACKUP FOLDER DETECTION
# =============================================================================
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "WINDOWS 11 GPO - RESTORE ORIGINAL SETTINGS (UNDO)" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script restores registry-based GPO settings only" -ForegroundColor White
Write-Host "="*70 -ForegroundColor Cyan

# Get current script location
$currentScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "`nScript location: $currentScriptDir" -ForegroundColor Gray

# Try to find 04A script in parent directory or current directory
$searchPaths = @(
    $currentScriptDir,
    (Split-Path -Parent $currentScriptDir)
)

$backupFolders = @()
foreach ($searchPath in $searchPaths) {
    $foundFolders = Get-ChildItem -Path $searchPath -Directory -Filter "BackUp-*" -ErrorAction SilentlyContinue
    if ($foundFolders) {
        $backupFolders += $foundFolders
        Write-Host "  Found backup folders in: $searchPath" -ForegroundColor Gray
    }
}

$backupFolders = $backupFolders | Sort-Object LastWriteTime -Descending

if ($backupFolders.Count -eq 0) {
    Write-Host "`nERROR: No backup folders found!" -ForegroundColor Red
    Write-Host "Searched in:" -ForegroundColor Gray
    foreach ($path in $searchPaths) {
        Write-Host "  - $path" -ForegroundColor Gray
    }
    Write-Host "`nPlease ensure you run this from the same directory as 04A script," -ForegroundColor Yellow
    Write-Host "or from the UNDO subfolder." -ForegroundColor Yellow
    pause
    exit 1
}

# Create System Restore Point
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    $restorePointName = "04B_UNDO_GPOs - " + (Get-Date -Format "yyyy-MM-dd HH:mm")
    Checkpoint-Computer -Description $restorePointName -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    Write-Host "  SUCCESS: System Restore Point created" -ForegroundColor Green
    Write-Host "  Name: $restorePointName" -ForegroundColor Gray
}
catch {
    Write-Host "  WARNING: Could not create System Restore Point" -ForegroundColor Yellow
    Write-Host "  Reason: $($_.Exception.Message)" -ForegroundColor Gray
    $proceed = Read-Host "`n  Continue without restore point? (y/N)"
    if ($proceed -ne 'y' -and $proceed -ne 'Y') {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        pause
        exit 0
    }
}

# Display found backup folders
Write-Host "`nFound $($backupFolders.Count) backup folder(s):" -ForegroundColor White
for ($i = 0; $i -lt [math]::Min($backupFolders.Count, 10); $i++) {
    $folder = $backupFolders[$i]
    $logCount = (Get-ChildItem -Path $folder.FullName -Filter "GPO_Reset_Log_*.txt" -ErrorAction SilentlyContinue).Count
    Write-Host "  [$($i+1)] $($folder.Name) - $logCount log file(s) - Modified: $($folder.LastWriteTime)" -ForegroundColor Gray
}

# Folder selection
if ($backupFolders.Count -eq 1) {
    $selectedBackupFolder = $backupFolders[0].FullName
    Write-Host "`nAuto-selected: $($backupFolders[0].Name)" -ForegroundColor Cyan
}
else {
    Write-Host "`nSelect backup folder to restore from:" -ForegroundColor White
    $selection = Read-Host "Enter number (1-$($backupFolders.Count)) or press Enter for most recent"
    
    if ($selection -eq '') {
        $selectedBackupFolder = $backupFolders[0].FullName
        Write-Host "Selected most recent: $($backupFolders[0].Name)" -ForegroundColor Cyan
    }
    elseif ($selection -match '^\d+$') {
        $idx = [int]$selection - 1
        if ($idx -ge 0 -and $idx -lt $backupFolders.Count) {
            $selectedBackupFolder = $backupFolders[$idx].FullName
            Write-Host "Selected: $($backupFolders[$idx].Name)" -ForegroundColor Cyan
        }
        else {
            Write-Host "ERROR: Invalid selection!" -ForegroundColor Red
            pause
            exit 1
        }
    }
    else {
        Write-Host "ERROR: Invalid input!" -ForegroundColor Red
        pause
        exit 1
    }
}

# Find log files
$logFiles = Get-ChildItem -Path $selectedBackupFolder -Filter "GPO_Reset_Log_*.txt" -ErrorAction SilentlyContinue | 
    Sort-Object LastWriteTime -Descending

if ($logFiles.Count -eq 0) {
    Write-Host "`nERROR: No log files found in: $selectedBackupFolder" -ForegroundColor Red
    pause
    exit 1
}

# Log file selection
if ($logFiles.Count -eq 1) {
    $selectedLogFile = $logFiles[0].FullName
    Write-Host "Auto-selected log: $($logFiles[0].Name)" -ForegroundColor Cyan
}
else {
    Write-Host "`nFound $($logFiles.Count) log files:" -ForegroundColor White
    for ($i = 0; $i -lt [math]::Min($logFiles.Count, 5); $i++) {
        Write-Host "  [$($i+1)] $($logFiles[$i].Name) - $($logFiles[$i].LastWriteTime)" -ForegroundColor Gray
    }
    
    $logSelection = Read-Host "`nSelect log (1-$($logFiles.Count)) or press Enter for most recent"
    
    if ($logSelection -eq '') {
        $selectedLogFile = $logFiles[0].FullName
        Write-Host "Selected most recent: $($logFiles[0].Name)" -ForegroundColor Cyan
    }
    elseif ($logSelection -match '^\d+$') {
        $idx = [int]$logSelection - 1
        if ($idx -ge 0 -and $idx -lt $logFiles.Count) {
            $selectedLogFile = $logFiles[$idx].FullName
            Write-Host "Selected: $($logFiles[$idx].Name)" -ForegroundColor Cyan
        }
        else {
            Write-Host "ERROR: Invalid selection!" -ForegroundColor Red
            pause
            exit 1
        }
    }
}
#endregion

#region PARSE LOG FILE
# =============================================================================
Write-Host "`nParsing log file..." -ForegroundColor Cyan

try {
    $logContent = Get-Content $selectedLogFile -Raw -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Could not read log file - $_" -ForegroundColor Red
    pause
    exit 1
}

# Parse log entries
$gpoEntries = @()
$lines = $logContent -split "`r?`n"
$currentEntry = @{}

foreach ($line in $lines) {
    $line = $line.Trim()
    
    if ($line -match '^\[.*\]$') {
        # Timestamp line - save previous entry if complete
        if ($currentEntry.Count -ge 4) {
            $gpoEntries += [PSCustomObject]$currentEntry
        }
        $currentEntry = @{}
    }
    elseif ($line -match '^Policy:\s*(.+)$') {
        $currentEntry.Policy = $matches[1].Trim()
    }
    elseif ($line -match '^Path:\s*(.+)$') {
        $currentEntry.Path = $matches[1].Trim()
    }
    elseif ($line -match '^Value:\s*(.+)$') {
        $currentEntry.ValueName = $matches[1].Trim()
    }
    elseif ($line -match '^OldValue:\s*(.+)$') {
        $currentEntry.OldValue = $matches[1].Trim()
    }
    elseif ($line -match '^NewValue:\s*(.+)$') {
        $currentEntry.NewValue = $matches[1].Trim()
    }
    elseif ($line -match '^Type:\s*(.+)$') {
        $currentEntry.Type = $matches[1].Trim()
    }
}

# Add last entry if complete
if ($currentEntry.Count -ge 4) {
    $gpoEntries += [PSCustomObject]$currentEntry
}

# Filter valid entries
$gpoEntries = $gpoEntries | Where-Object { 
    $_.Path -and $_.ValueName -and $_.OldValue -and ($_.Policy -match "Policy")
}

if ($gpoEntries.Count -eq 0) {
    Write-Host "ERROR: No valid GPO entries found in log!" -ForegroundColor Red
    pause
    exit 1
}

Write-Host "  SUCCESS: Parsed $($gpoEntries.Count) GPO changes" -ForegroundColor Green

# Protected policies
$protectedPolicies = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DisableWindowsUpdateAccess"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableAntiSpyware"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name="RemoveWindowsStore"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name="DisableStoreApps"}
)
#endregion

#region IMPORTANT WARNING
# =============================================================================
Write-Host "`n" + "!"*70 -ForegroundColor Yellow
Write-Host "UNDO CAPABILITIES AND LIMITATIONS" -ForegroundColor Yellow
Write-Host "!"*70 -ForegroundColor Yellow
Write-Host "CAN BE RESTORED:" -ForegroundColor Green
Write-Host "  - Registry-based GPO settings ($($gpoEntries.Count) entries)" -ForegroundColor Green
Write-Host ""
Write-Host "CANNOT BE RESTORED BY THIS SCRIPT:" -ForegroundColor Red
Write-Host "  - Security policies (secedit) - Use System Restore" -ForegroundColor Red
Write-Host "  - LGPO.exe operations - Use System Restore or manual backup" -ForegroundColor Red
Write-Host ""
Write-Host "Protected policies will be skipped (not modified)." -ForegroundColor Yellow
Write-Host "!"*70 -ForegroundColor Yellow

$confirm = Read-Host "`nType 'YES' (uppercase) to proceed with restoration"
if ($confirm -ne 'YES') {
    Write-Host "`nOperation cancelled by user." -ForegroundColor Yellow
    pause
    exit 0
}
#endregion

#region RESTORE GPO SETTINGS
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "RESTORING REGISTRY-BASED GPO SETTINGS" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

$restoredCount = 0
$skippedCount = 0
$errorCount = 0

# Create undo log for this operation
$undoLogFile = Join-Path $selectedBackupFolder "GPO_UNDO_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$undoLogContent = @()
$undoLogContent += "="*70
$undoLogContent += "GPO UNDO OPERATION LOG"
$undoLogContent += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$undoLogContent += "Script: 04B_Undo_Reset_GPOs_Default.ps1"
$undoLogContent += "Source Backup: $(Split-Path $selectedBackupFolder -Leaf)"
$undoLogContent += "Source Log: $(Split-Path $selectedLogFile -Leaf)"
$undoLogContent += "="*70
$undoLogContent += ""

foreach ($entry in $gpoEntries) {
    $policyPath = $entry.Path
    $valueName = $entry.ValueName
    $oldValue = $entry.OldValue
    $valueType = if ($entry.Type) { $entry.Type } else { "DWORD" }
    
    # Check if protected
    $isProtected = $protectedPolicies | Where-Object { 
        $_.Path -eq $policyPath -and $_.Name -eq $valueName 
    }
    
    if ($isProtected) {
        Write-Host "  Skipping protected: $valueName" -ForegroundColor Yellow
        $undoLogContent += "[SKIPPED - Protected] $policyPath\$valueName"
        $skippedCount++
        continue
    }
    
    Write-Host "`n  Restoring: $valueName" -ForegroundColor Gray
    Write-Host "    Path: $policyPath" -ForegroundColor DarkGray
    Write-Host "    Original value: $oldValue" -ForegroundColor DarkGray
    
    try {
        # Handle different OldValue formats
        if ($oldValue -eq "[NOT_EXISTS]" -or $oldValue -eq "[NULL]" -or $oldValue -eq "[DELETED]") {
            # Original didn't exist - remove current value
            if (Test-Path $policyPath) {
                Remove-ItemProperty -Path $policyPath -Name $valueName -ErrorAction SilentlyContinue -Force
                Write-Host "    SUCCESS: Deleted (original didn't exist)" -ForegroundColor Green
                $undoLogContent += "[DELETED] $policyPath\$valueName - Original: $oldValue"
            }
            else {
                Write-Host "    INFO: Path doesn't exist (already correct)" -ForegroundColor Gray
            }
            $restoredCount++
        }
        elseif ($oldValue -match '^\[ERROR:') {
            # Original had error - skip
            Write-Host "    SKIPPED: Original value had error" -ForegroundColor Yellow
            $undoLogContent += "[SKIPPED - Error in original] $policyPath\$valueName"
            $skippedCount++
        }
        else {
            # Restore original value
            if (-not (Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null
            }
            
            # Determine value type and set
            if ($oldValue -match '^\d+$' -and $valueType -eq "DWORD") {
                Set-ItemProperty -Path $policyPath -Name $valueName -Value ([int]$oldValue) -Type DWORD -Force -ErrorAction Stop
                Write-Host "    SUCCESS: Restored DWORD = $oldValue" -ForegroundColor Green
                $undoLogContent += "[RESTORED] $policyPath\$valueName = $oldValue (DWORD)"
            }
            elseif ($oldValue -match '^\d+$') {
                Set-ItemProperty -Path $policyPath -Name $valueName -Value ([int]$oldValue) -Type DWORD -Force -ErrorAction Stop
                Write-Host "    SUCCESS: Restored numeric = $oldValue" -ForegroundColor Green
                $undoLogContent += "[RESTORED] $policyPath\$valueName = $oldValue"
            }
            else {
                Set-ItemProperty -Path $policyPath -Name $valueName -Value $oldValue -Type String -Force -ErrorAction Stop
                Write-Host "    SUCCESS: Restored string = $oldValue" -ForegroundColor Green
                $undoLogContent += "[RESTORED] $policyPath\$valueName = `"$oldValue`" (String)"
            }
            $restoredCount++
        }
    }
    catch {
        Write-Host "    ERROR: Failed to restore - $_" -ForegroundColor Red
        $undoLogContent += "[ERROR] $policyPath\$valueName - Error: $_"
        $errorCount++
    }
}
#endregion

#region APPLY CHANGES
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "APPLYING CHANGES" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

# Save undo log
Write-Host "`nSaving undo log..." -ForegroundColor Cyan
try {
    $undoLogContent += ""
    $undoLogContent += "="*70
    $undoLogContent += "END OF LOG"
    $undoLogContent += "="*70
    $undoLogContent | Out-File -FilePath $undoLogFile -Encoding UTF8
    Write-Host "  SUCCESS: Log saved to: $undoLogFile" -ForegroundColor Green
}
catch {
    Write-Host "  WARNING: Could not save log - $_" -ForegroundColor Yellow
}

# Refresh Group Policy
Write-Host "`nRefreshing Group Policy..." -ForegroundColor Cyan
try {
    $gpResult = gpupdate /force 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  SUCCESS: Group Policy refreshed" -ForegroundColor Green
    }
    else {
        Write-Host "  WARNING: gpupdate returned code: $LASTEXITCODE" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  WARNING: gpupdate had issues" -ForegroundColor Yellow
}
#endregion

#region COMPLETION SUMMARY
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "GPO UNDO OPERATION COMPLETE" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nSUMMARY:" -ForegroundColor White
Write-Host "  Registry policies restored: $restoredCount" -ForegroundColor Cyan
Write-Host "  Protected policies skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "  Errors encountered: $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
Write-Host "  System Restore Point: Created" -ForegroundColor Green
Write-Host "  Backup folder: $selectedBackupFolder" -ForegroundColor Gray
Write-Host "  Undo log: $(Split-Path $undoLogFile -Leaf)" -ForegroundColor Gray

Write-Host "`nRESTORATION STATUS:" -ForegroundColor White
Write-Host "  Registry-based GPO settings: RESTORED" -ForegroundColor Green
Write-Host "  Security policies (secedit): NOT RESTORED" -ForegroundColor Yellow
Write-Host "  LGPO.exe operations: NOT RESTORED" -ForegroundColor Yellow

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
Write-Host "  1. Reboot recommended for all changes to take effect" -ForegroundColor Gray
Write-Host "  2. For security policies: Use System Restore Point" -ForegroundColor Gray
Write-Host "  3. For LGPO operations: Use System Restore or manual backup" -ForegroundColor Gray

if ($errorCount -gt 0) {
    Write-Host "`nWARNING: Some errors occurred during restoration." -ForegroundColor Red
    Write-Host "Check undo log for details: $undoLogFile" -ForegroundColor Gray
}

Write-Host "`n" + "="*70 -ForegroundColor Green

$reboot = Read-Host "`nReboot now? (Y/N)"
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