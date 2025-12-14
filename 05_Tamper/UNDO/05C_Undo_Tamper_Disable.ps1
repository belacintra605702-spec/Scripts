#requires -RunAsAdministrator
#requires -Version 5.1

<#
.SYNOPSIS
    Restores Tamper Protection to original state
.DESCRIPTION
    Reverses all changes made by 05A_Tamper_Disable.ps1
    Restores registry, services, and scheduled tasks from backups
.NOTES
    Windows 11 Pro - Complete restoration
#>

#region ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`nAdministrative privileges required..." -ForegroundColor Yellow
    try {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
        exit
    }
    catch {
        Write-Host "`nERROR: Failed to elevate privileges!" -ForegroundColor Red
        pause
        exit 1
    }
}
#endregion

#region SCRIPT CONFIGURATION
$ScriptName = "05C_Undo_Tamper_Disable"
$RestorePointName = "${ScriptName}_$(Get-Date -Format 'MM-dd-yyyy_HHmmss')"
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$BackupDir = Join-Path $ScriptDir "UNDO\Backup"
#endregion

#region FUNCTIONS
function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Type) {
        "SUCCESS" { "Green" }
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        default { "Gray" }
    }
    Write-Host "$timestamp $Message" -ForegroundColor $color
}

function Create-SystemRestorePoint {
    try {
        Write-Status "Creating System Restore Point: $RestorePointName"
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description $RestorePointName -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Status "System Restore Point created" -Type "SUCCESS"
        return $true
    }
    catch {
        Write-Status "Failed to create System Restore Point: $_" -Type "ERROR"
        return $false
    }
}

function Find-LatestBackup {
    param([string]$Pattern)
    
    if (-not (Test-Path $BackupDir)) {
        Write-Status "Backup directory not found: $BackupDir" -Type "ERROR"
        return $null
    }
    
    $backupFiles = Get-ChildItem -Path $BackupDir -Filter $Pattern -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending
    
    if ($backupFiles.Count -eq 0) {
        Write-Status "No backup files found matching: $Pattern" -Type "ERROR"
        return $null
    }
    
    $latestBackup = $backupFiles[0]
    Write-Status "Found backup: $($latestBackup.Name)" -Type "SUCCESS"
    Write-Status "Created: $($latestBackup.LastWriteTime)" -Type "INFO"
    
    return $latestBackup.FullName
}

function Restore-RegistryFromBackup {
    param([string]$BackupFile)
    
    if (-not (Test-Path $BackupFile)) {
        Write-Status "Backup file not found: $BackupFile" -Type "ERROR"
        return $false
    }
    
    try {
        Write-Status "Restoring registry from backup..."
        
        $process = Start-Process "reg.exe" -ArgumentList "import `"$BackupFile`"" -Wait -NoNewWindow -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Status "Registry restored successfully" -Type "SUCCESS"
            return $true
        }
        else {
            Write-Status "Registry restore failed with exit code: $($process.ExitCode)" -Type "ERROR"
            return $false
        }
    }
    catch {
        Write-Status "Failed to restore registry: $_" -Type "ERROR"
        return $false
    }
}

function Restore-DefenderServices {
    param([string]$BackupFile)
    
    if (-not (Test-Path $BackupFile)) {
        Write-Status "Services backup not found, using default restoration" -Type "WARNING"
        # Restore to default enabled state
        $defaultServices = @{
            'WinDefend' = @{StartType='Automatic'; Status='Running'}
            'SecurityHealthService' = @{StartType='Automatic'; Status='Running'}
            'Sense' = @{StartType='Manual'; Status='Running'}
            'WdNisSvc' = @{StartType='Manual'; Status='Running'}
        }
        
        foreach ($svcName in $defaultServices.Keys) {
            try {
                $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($service) {
                    Set-Service -Name $svcName -StartupType $defaultServices[$svcName].StartType -ErrorAction Stop
                    if ($defaultServices[$svcName].Status -eq 'Running') {
                        Start-Service -Name $svcName -ErrorAction Stop
                    }
                    Write-Status "? Restored service: $svcName" -Type "SUCCESS"
                }
            }
            catch {
                Write-Status "? Failed to restore service: $svcName - $_" -Type "WARNING"
            }
        }
        return $true
    }
    
    try {
        Write-Status "Restoring services from backup..."
        $serviceStates = Get-Content $BackupFile -Raw | ConvertFrom-Json
        
        foreach ($svcName in $serviceStates.PSObject.Properties.Name) {
            try {
                $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($service) {
                    $targetStartType = $serviceStates.$svcName.StartType
                    $targetStatus = $serviceStates.$svcName.Status
                    
                    Set-Service -Name $svcName -StartupType $targetStartType -ErrorAction Stop
                    
                    if ($targetStatus -eq 'Running') {
                        Start-Service -Name $svcName -ErrorAction Stop
                    }
                    
                    Write-Status "? Restored service: $svcName to $targetStartType/$targetStatus" -Type "SUCCESS"
                }
            }
            catch {
                Write-Status "? Failed to restore service: $svcName - $_" -Type "WARNING"
            }
        }
        
        return $true
    }
    catch {
        Write-Status "Failed to restore services: $_" -Type "ERROR"
        return $false
    }
}

function Restore-DefenderTasks {
    try {
        Write-Status "Re-enabling Defender scheduled tasks..."
        
        $tasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\*' -ErrorAction SilentlyContinue
        
        foreach ($task in $tasks) {
            try {
                if ($task.State -eq 'Disabled') {
                    Enable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                    Write-Status "? Enabled task: $($task.TaskName)" -Type "SUCCESS"
                }
            }
            catch {
                Write-Status "? Failed to enable task: $($task.TaskName)" -Type "WARNING"
            }
        }
        
        return $true
    }
    catch {
        Write-Status "Failed to restore scheduled tasks: $_" -Type "ERROR"
        return $false
    }
}

function Enable-TamperProtectionExplicitly {
    Write-Status "Explicitly re-enabling Tamper Protection..."
    
    try {
        # Primary method: HKLM Features
        $path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "TamperProtection" -Value 5 -Type DWord -Force -ErrorAction Stop
            Write-Status "? Set HKLM\...\Features\TamperProtection = 5" -Type "SUCCESS"
        }
        
        # Remove disable flags
        $pathsToClean = @(
            "HKCU:\Software\Microsoft\Windows Defender",
            "HKCU:\Software\Microsoft\Windows Defender\Features",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        )
        
        foreach ($regPath in $pathsToClean) {
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "DisableAntiTamper" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $regPath -Name "TamperProtection" -ErrorAction SilentlyContinue
            }
        }
        
        return $true
    }
    catch {
        Write-Status "Failed to explicitly enable Tamper Protection: $_" -Type "WARNING"
        return $false
    }
}

function Verify-Restoration {
    Write-Status "Verifying restoration..."
    
    $checks = @()
    
    # Check 1: HKLM Features\TamperProtection should be 5 or 1
    try {
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        $isRestored = ($null -ne $val -and $val.TamperProtection -in @(5, 1))
        $checks += @{Name="HKLM Features\TamperProtection"; Restored=$isRestored}
        Write-Host "  HKLM\...\Features\TamperProtection: " -NoNewline
        Write-Host "$(if($isRestored){"RESTORED ($($val.TamperProtection))"}else{'NOT RESTORED'})" -ForegroundColor $(if($isRestored){'Green'}else{'Red'})
    }
    catch {
        $checks += @{Name="HKLM Features\TamperProtection"; Restored=$false}
        Write-Host "  HKLM\...\Features\TamperProtection: Error checking" -ForegroundColor Red
    }
    
    # Check 2: HKCU DisableAntiTamper should not exist or be 0
    try {
        $val = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Defender" -Name "DisableAntiTamper" -ErrorAction SilentlyContinue
        $isRestored = ($null -eq $val -or $val.DisableAntiTamper -eq 0)
        $checks += @{Name="HKCU DisableAntiTamper"; Restored=$isRestored}
        Write-Host "  HKCU\...\DisableAntiTamper: " -NoNewline
        Write-Host "$(if($isRestored){'RESTORED'}else{'NOT RESTORED'})" -ForegroundColor $(if($isRestored){'Green'}else{'Red'})
    }
    catch {
        $checks += @{Name="HKCU DisableAntiTamper"; Restored=$true}
        Write-Host "  HKCU\...\DisableAntiTamper: RESTORED (removed)" -ForegroundColor Green
    }
    
    # Check 3: Services status
    $services = @('WinDefend', 'SecurityHealthService')
    foreach ($svcName in $services) {
        try {
            $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($service) {
                $isRestored = ($service.StartType -ne 'Disabled')
                $checks += @{Name="Service: $svcName"; Restored=$isRestored}
                Write-Host "  Service $svcName`: " -NoNewline
                Write-Host "$(if($isRestored){"RESTORED ($($service.StartType))"}else{'NOT RESTORED (Disabled)'})" -ForegroundColor $(if($isRestored){'Green'}else{'Red'})
            }
        }
        catch {
            Write-Host "  Service $svcName`: Error checking" -ForegroundColor Yellow
        }
    }
    
    if ($checks.Count -gt 0) {
        $restoredCount = ($checks | Where-Object { $_.Restored }).Count
        $percentage = [math]::Round(($restoredCount / $checks.Count) * 100)
        
        Write-Status "`nRestoration verification: $restoredCount of $($checks.Count) checks passed ($percentage%)"
        
        if ($percentage -eq 100) {
            Write-Status "? COMPLETE RESTORATION SUCCESSFUL" -Type "SUCCESS"
        }
        elseif ($percentage -ge 80) {
            Write-Status "? Mostly restored ($percentage%)" -Type "SUCCESS"
        }
        else {
            Write-Status "? Partial restoration ($percentage%) - manual verification recommended" -Type "WARNING"
        }
    }
    
    return $checks
}
#endregion

#region MAIN EXECUTION
Clear-Host
Write-Host "`n=========================================================" -ForegroundColor Cyan
Write-Host "       RESTORE TAMPER PROTECTION (UNDO)" -ForegroundColor Cyan
Write-Host "            Complete Restoration Process" -ForegroundColor Cyan
Write-Host "=========================================================`n" -ForegroundColor Cyan

Write-Host "This will restore Tamper Protection to its original state.`n" -ForegroundColor Yellow
$confirm = Read-Host "Do you want to continue? (y/n)"
if ($confirm -notmatch '^[yY]') {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Step 1: Find backups
Write-Host "`n[STEP 1] Looking for backup files..." -ForegroundColor Cyan
$regBackup = Find-LatestBackup -Pattern "05A_Tamper_Disable_Backup_*.reg"
$svcBackup = Find-LatestBackup -Pattern "05A_Tamper_Disable_Services_*.json"

if (-not $regBackup) {
    Write-Host "`n? Registry backup not found. Cannot proceed safely." -ForegroundColor Red
    Write-Host "Backup directory: $BackupDir" -ForegroundColor Yellow
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# Step 2: Create System Restore Point
Write-Host "`n[STEP 2] Creating System Restore Point..." -ForegroundColor Cyan
if (-not (Create-SystemRestorePoint)) {
    $continue = Read-Host "Continue without System Restore Point? (y/n)"
    if ($continue -notmatch '^[yY]') { exit 1 }
}

# Step 3: Restore registry
Write-Host "`n[STEP 3] Restoring registry from backup..." -ForegroundColor Cyan
$regSuccess = Restore-RegistryFromBackup -BackupFile $regBackup

if (-not $regSuccess) {
    Write-Host "`n? Registry restore failed. Aborting." -ForegroundColor Red
    Write-Host "`nPress any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# Step 4: Restore services
Write-Host "`n[STEP 4] Restoring Windows Defender services..." -ForegroundColor Cyan
Restore-DefenderServices -BackupFile $svcBackup

# Step 5: Restore scheduled tasks
Write-Host "`n[STEP 5] Restoring scheduled tasks..." -ForegroundColor Cyan
Restore-DefenderTasks

# Step 6: Explicitly enable Tamper Protection
Write-Host "`n[STEP 6] Explicitly enabling Tamper Protection..." -ForegroundColor Cyan
Enable-TamperProtectionExplicitly

# Step 7: Verify restoration
Write-Host "`n[STEP 7] Verifying restoration..." -ForegroundColor Cyan
$verification = Verify-Restoration

# Summary
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "UNDO OPERATION COMPLETED" -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "Registry backup used: $(Split-Path $regBackup -Leaf)" -ForegroundColor Gray
if ($svcBackup) {
    Write-Host "Services backup used: $(Split-Path $svcBackup -Leaf)" -ForegroundColor Gray
}
Write-Host "`n??  RESTART REQUIRED for complete restoration" -ForegroundColor Yellow
Write-Host "`nAfter restart, verify Tamper Protection in Windows Security app" -ForegroundColor Yellow
Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
#endregion