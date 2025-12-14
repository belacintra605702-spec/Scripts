# =============================================================================
# Script: 04A_Reset_GPOs_Default.ps1
# Purpose: Reset ALL Local Group Policy Objects (GPO) to Windows 11 default settings
#          for both Computer and User configurations.
# Requirements: Run as Administrator, Windows 11
# Encoding: ANSI
# Backup Structure: Creates BackUp-dd-MM-yyyy folder in script directory
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

#region INITIALIZATION AND BACKUP FOLDER CREATION
# =============================================================================
Clear-Host
Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "WINDOWS 11 GPO - RESET TO DEFAULT SETTINGS" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "This script will reset ALL Group Policy Objects to Windows 11 defaults" -ForegroundColor White
Write-Host "="*70 -ForegroundColor Cyan

# Create backup folder with date structure
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backupDate = Get-Date -Format "dd-MM-yyyy"
$backupFolder = Join-Path $scriptDir "BackUp-$backupDate"

Write-Host "`nCreating backup folder..." -ForegroundColor White
try {
    if (-not (Test-Path $backupFolder)) {
        New-Item -ItemType Directory -Path $backupFolder -Force -ErrorAction Stop | Out-Null
    }
    Write-Host "  SUCCESS: Backup folder ready: $backupFolder" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: Could not create backup folder!" -ForegroundColor Red
    Write-Host "  Error details: $_" -ForegroundColor Gray
    pause
    exit 1
}

# Create system restore point
Write-Host "`nCreating System Restore Point..." -ForegroundColor Cyan
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    $restorePointName = "04A_Reset_GPOs - " + (Get-Date -Format "yyyy-MM-dd HH:mm")
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

# Initialize log file
$logFile = Join-Path $backupFolder "GPO_Reset_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$undoLog = @()
$undoLog += "="*70
$undoLog += "GPO RESET OPERATION LOG"
$undoLog += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$undoLog += "Script: 04A_Reset_GPOs_Default.ps1"
$undoLog += "Backup Folder: $backupFolder"
$undoLog += "="*70
$undoLog += ""

function Add-ToUndoLog {
    param(
        [string]$policyName,
        [string]$registryPath,
        [string]$valueName,
        [string]$oldValue,
        [string]$newValue,
        [string]$valueType = "DWORD"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @"
[$timestamp]
Policy: $policyName
Path: $registryPath
Value: $valueName
OldValue: $oldValue
NewValue: $newValue
Type: $valueType
"@
    $script:undoLog += $logEntry
    $script:undoLog += "-"*40
}

function Backup-CurrentValue {
    param(
        [string]$registryPath,
        [string]$valueName
    )
    try {
        if (Test-Path $registryPath) {
            $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
            if ($null -ne $currentValue) {
                $val = $currentValue.$valueName
                if ($null -eq $val) {
                    return "[NULL]"
                }
                return $val.ToString()
            }
        }
        return "[NOT_EXISTS]"
    }
    catch {
        return "[ERROR: $_]"
    }
}
#endregion

#region CRITICAL POLICY PROTECTION LIST
# =============================================================================
$protectedPolicies = @(
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DisableWindowsUpdateAccess"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableAntiSpyware"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name="RemoveWindowsStore"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name="DisableStoreApps"}
)

Write-Host "`nProtected policies (will NOT be modified):" -ForegroundColor Yellow
foreach ($policy in $protectedPolicies) {
    Write-Host "  - $($policy.Path)\$($policy.Name)" -ForegroundColor Gray
}
#endregion

#region IMPORTANT WARNING
# =============================================================================
Write-Host "`n" + "!"*70 -ForegroundColor Red
Write-Host "IMPORTANT: NON-REVERSIBLE ACTIONS" -ForegroundColor Red
Write-Host "!"*70 -ForegroundColor Red
Write-Host "The following actions CANNOT be automatically reversed by UNDO script:" -ForegroundColor White
Write-Host "  1. Security policies reset (secedit) - passwords, auditing, user rights" -ForegroundColor Yellow
Write-Host "  2. LGPO.exe operations (if used)" -ForegroundColor Yellow
Write-Host ""
Write-Host "These can only be restored via System Restore Point." -ForegroundColor White
Write-Host "Registry-based GPO settings CAN be reversed by UNDO script." -ForegroundColor Green
Write-Host "!"*70 -ForegroundColor Red

$confirm = Read-Host "`nType 'YES' (uppercase) to proceed with GPO reset"
if ($confirm -ne 'YES') {
    Write-Host "`nOperation cancelled by user." -ForegroundColor Yellow
    pause
    exit 0
}
#endregion

#region STEP 1: RESET SECURITY POLICIES
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 1: RESETTING SECURITY POLICIES (secedit)" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White
Write-Host "WARNING: This action is NOT reversible by UNDO script" -ForegroundColor Yellow

try {
    Write-Host "`nResetting all security policies to Windows 11 defaults..." -ForegroundColor Cyan
    $secEditOutput = secedit /configure /cfg "$env:windir\inf\defltbase.inf" /db defltbase.sdb /verbose 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  SUCCESS: Security policies reset to defaults" -ForegroundColor Green
        $undoLog += "ACTION: secedit /configure - Security policies reset (NOT REVERSIBLE)"
        $undoLog += "NOTE: Use System Restore to revert security policies"
        $undoLog += ""
    }
    else {
        Write-Host "  WARNING: secedit returned code: $LASTEXITCODE" -ForegroundColor Yellow
        $undoLog += "ACTION: secedit attempted - exit code: $LASTEXITCODE"
        $undoLog += ""
    }
}
catch {
    Write-Host "  ERROR: Failed to reset security policies - $_" -ForegroundColor Red
    $undoLog += "ERROR: secedit failed - $_"
    $undoLog += ""
}
#endregion

#region STEP 2: RESET COMPUTER CONFIGURATION POLICIES
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 2: RESETTING COMPUTER CONFIGURATION POLICIES" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

$computerPoliciesToReset = @(
    # Personalization
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreen"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoChangingLockScreen"; DefaultValue=$null},
    
    # System
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="VerboseStatus"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableStatusMessages"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ShutdownWithoutLogon"; DefaultValue=1},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="UndockWithoutLogon"; DefaultValue=1},
    
    # Privacy/Telemetry
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; DefaultValue=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DoNotShowFeedbackNotifications"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="DisableInventory"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name="AITEnable"; DefaultValue=$null},
    
    # Windows Features
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableSoftLanding"; DefaultValue=$null},
    
    # Location and Sensors
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableLocation"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableWindowsLocationProvider"; DefaultValue=$null},
    
    # Tablet PC
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name="PreventHandwritingDataSharing"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name="PreventHandwritingErrorReports"; DefaultValue=$null},
    
    # Windows Update (non-critical)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="SetDisableUXWUAccess"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ExcludeWUDriversInQualityUpdate"; DefaultValue=$null},
    
    # Error Reporting
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name="Disabled"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name="DontSendAdditionalData"; DefaultValue=$null},
    
    # OneDrive
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name="DisableFileSyncNGSC"; DefaultValue=$null},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name="DisableFileSync"; DefaultValue=$null},
    
    # Storage Sense
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense"; Name="AllowStorageSenseGlobal"; DefaultValue=$null},
    
    # Game DVR
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"; DefaultValue=$null}
)

$computerPoliciesReset = 0
foreach ($policy in $computerPoliciesToReset) {
    $isProtected = $protectedPolicies | Where-Object { $_.Path -eq $policy.Path -and $_.Name -eq $policy.Name }
    
    if ($isProtected) {
        Write-Host "  Skipping protected policy: $($policy.Name)" -ForegroundColor Yellow
        continue
    }
    
    try {
        $oldValue = Backup-CurrentValue -registryPath $policy.Path -valueName $policy.Name
        
        if ($oldValue -eq "[NOT_EXISTS]" -and $policy.DefaultValue -eq $null) {
            # Policy doesn't exist and shouldn't exist - skip
            continue
        }
        
        if ($policy.DefaultValue -eq $null) {
            # Remove policy
            if (Test-Path $policy.Path) {
                Remove-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue -Force
                Write-Host "  Removed: $($policy.Name)" -ForegroundColor Green
                Add-ToUndoLog -policyName "Computer Policy" -registryPath $policy.Path -valueName $policy.Name -oldValue $oldValue -newValue "[DELETED]"
                $computerPoliciesReset++
            }
        }
        else {
            # Set to default value
            if (-not (Test-Path $policy.Path)) {
                New-Item -Path $policy.Path -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.DefaultValue -Type DWORD -Force -ErrorAction Stop
            Write-Host "  Set to default: $($policy.Name) = $($policy.DefaultValue)" -ForegroundColor Green
            Add-ToUndoLog -policyName "Computer Policy" -registryPath $policy.Path -valueName $policy.Name -oldValue $oldValue -newValue $policy.DefaultValue
            $computerPoliciesReset++
        }
    }
    catch {
        Write-Host "  WARNING: Could not process $($policy.Name) - $_" -ForegroundColor Yellow
    }
}

Write-Host "`n  Summary: $computerPoliciesReset computer policies reset" -ForegroundColor Cyan
#endregion

#region STEP 3: RESET USER CONFIGURATION POLICIES
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 3: RESETTING USER CONFIGURATION POLICIES" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

$userPoliciesToReset = @(
    # Explorer
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDrives"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoNetConnectDisconnect"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoRun"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoClose"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoControlPanel"; DefaultValue=$null},
    
    # System
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableLockWorkstation"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableTaskMgr"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableRegistryTools"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableCMD"; DefaultValue=$null},
    
    # Control Panel/Desktop
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; Name="ScreenSaveActive"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; Name="ScreenSaveTimeout"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"; Name="ScreenSaverIsSecure"; DefaultValue=$null},
    
    # Windows Installer
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="DisableUserInstalls"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; DefaultValue=$null},
    
    # Notifications
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoToastApplicationNotification"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"; Name="NoCloudApplicationNotification"; DefaultValue=$null},
    
    # Start Menu/Taskbar
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableNotificationCenter"; DefaultValue=$null},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="HidePeopleBar"; DefaultValue=$null}
)

$userPoliciesReset = 0
foreach ($policy in $userPoliciesToReset) {
    try {
        $oldValue = Backup-CurrentValue -registryPath $policy.Path -valueName $policy.Name
        
        if ($oldValue -eq "[NOT_EXISTS]" -and $policy.DefaultValue -eq $null) {
            continue
        }
        
        if ($policy.DefaultValue -eq $null) {
            if (Test-Path $policy.Path) {
                Remove-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue -Force
                Write-Host "  Removed user policy: $($policy.Name)" -ForegroundColor Green
                Add-ToUndoLog -policyName "User Policy" -registryPath $policy.Path -valueName $policy.Name -oldValue $oldValue -newValue "[DELETED]"
                $userPoliciesReset++
            }
        }
        else {
            if (-not (Test-Path $policy.Path)) {
                New-Item -Path $policy.Path -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path $policy.Path -Name $policy.Name -Value $policy.DefaultValue -Type DWORD -Force -ErrorAction Stop
            Write-Host "  Set to default: $($policy.Name) = $($policy.DefaultValue)" -ForegroundColor Green
            Add-ToUndoLog -policyName "User Policy" -registryPath $policy.Path -valueName $policy.Name -oldValue $oldValue -newValue $policy.DefaultValue
            $userPoliciesReset++
        }
    }
    catch {
        Write-Host "  WARNING: Could not process $($policy.Name) - $_" -ForegroundColor Yellow
    }
}

Write-Host "`n  Summary: $userPoliciesReset user policies reset" -ForegroundColor Cyan
#endregion

#region STEP 4: LGPO.EXE ENHANCED RESET (OPTIONAL)
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 4: LGPO.EXE ENHANCED RESET (OPTIONAL)" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

$lgpoPath = "C:\Windows\System32\LGPO.exe"
$lgpoUsed = $false

if (Test-Path $lgpoPath) {
    Write-Host "`nLGPO.exe found at: $lgpoPath" -ForegroundColor Yellow
    Write-Host "LGPO.exe can reset additional GPO settings not covered by registry." -ForegroundColor Gray
    Write-Host "WARNING: LGPO.exe operations are NOT reversible by UNDO script." -ForegroundColor Yellow
    
    $useLGPO = Read-Host "`nUse LGPO.exe for enhanced reset? (Y/N)"
    
    if ($useLGPO -eq 'Y' -or $useLGPO -eq 'y') {
        Write-Host "`nExecuting LGPO.exe operations..." -ForegroundColor Cyan
        
        try {
            # Backup current GPO with LGPO
            $lgpoBackupFolder = Join-Path $backupFolder "LGPO_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Write-Host "  Backing up current GPO state..." -ForegroundColor Gray
            New-Item -ItemType Directory -Path $lgpoBackupFolder -Force -ErrorAction Stop | Out-Null
            
            $backupResult = Start-Process $lgpoPath -ArgumentList "/b `"$lgpoBackupFolder`"" -Wait -NoNewWindow -PassThru
            if ($backupResult.ExitCode -eq 0) {
                Write-Host "  SUCCESS: Current GPO state backed up" -ForegroundColor Green
                $undoLog += "LGPO_BACKUP: $lgpoBackupFolder (NOT auto-reversible)"
            }
            else {
                Write-Host "  WARNING: LGPO backup returned exit code: $($backupResult.ExitCode)" -ForegroundColor Yellow
            }
            
            $lgpoUsed = $true
            $undoLog += "ACTION: LGPO.exe used (NOT REVERSIBLE - use backup folder manually)"
            $undoLog += ""
        }
        catch {
            Write-Host "  ERROR: LGPO.exe operations failed - $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  Skipped LGPO.exe as per user choice" -ForegroundColor Gray
    }
}
else {
    Write-Host "`nLGPO.exe not found (optional tool, not included in Windows)" -ForegroundColor Gray
}
#endregion

#region STEP 5: APPLY CHANGES
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor White
Write-Host "STEP 5: APPLYING CHANGES" -ForegroundColor White
Write-Host "="*70 -ForegroundColor White

# Refresh Group Policy
Write-Host "`nRefreshing Group Policy..." -ForegroundColor Cyan
try {
    $gpResult = gpupdate /force 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  SUCCESS: Group Policy refreshed" -ForegroundColor Green
        $undoLog += "ACTION: gpupdate /force executed"
        $undoLog += ""
    }
    else {
        Write-Host "  WARNING: gpupdate returned code: $LASTEXITCODE" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  WARNING: gpupdate had issues" -ForegroundColor Yellow
}

# Save undo log
Write-Host "`nSaving undo log..." -ForegroundColor Cyan
try {
    $undoLog += "="*70
    $undoLog += "END OF LOG"
    $undoLog += "="*70
    $undoLog | Out-File -FilePath $logFile -Encoding UTF8
    Write-Host "  SUCCESS: Log saved to: $logFile" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: Could not save log file - $_" -ForegroundColor Red
}
#endregion

#region COMPLETION SUMMARY
# =============================================================================
Write-Host "`n" + "="*70 -ForegroundColor Green
Write-Host "GPO RESET COMPLETE" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Green

Write-Host "`nSUMMARY:" -ForegroundColor White
Write-Host "  Computer policies reset: $computerPoliciesReset" -ForegroundColor Cyan
Write-Host "  User policies reset: $userPoliciesReset" -ForegroundColor Cyan
Write-Host "  Protected policies (not modified): $($protectedPolicies.Count)" -ForegroundColor Yellow
Write-Host "  Security policies reset: Yes (secedit)" -ForegroundColor Cyan
Write-Host "  LGPO.exe used: $(if ($lgpoUsed) { 'Yes' } else { 'No' })" -ForegroundColor Cyan
Write-Host "  System Restore Point: Created" -ForegroundColor Green
Write-Host "  Backup folder: $backupFolder" -ForegroundColor Gray

Write-Host "`nREVERSIBLE BY UNDO SCRIPT:" -ForegroundColor White
Write-Host "  - Registry-based GPO settings: YES" -ForegroundColor Green
Write-Host "  - Security policies (secedit): NO" -ForegroundColor Red
Write-Host "  - LGPO.exe operations: NO" -ForegroundColor Red

Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Reboot recommended for all changes to take effect" -ForegroundColor Gray
Write-Host "  2. UNDO script: 04B_Undo_Reset_GPOs_Default.ps1" -ForegroundColor Gray
Write-Host "  3. For full restore: Use System Restore Point" -ForegroundColor Gray

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