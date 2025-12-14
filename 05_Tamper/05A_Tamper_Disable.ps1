#requires -RunAsAdministrator
#requires -Version 5.1

<#
.SYNOPSIS
    Disables Windows Defender Tamper Protection completely
.DESCRIPTION
    Aggressive script to disable Tamper Protection using all available methods
    Creates backups for undo operation
.NOTES
    Windows 11 Pro - Personal use only
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
$ScriptName = "05A_Tamper_Disable"
$RestorePointName = "${ScriptName}_$(Get-Date -Format 'MM-dd-yyyy_HHmmss')"
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$BackupDir = Join-Path $ScriptDir "UNDO\Backup"
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$BackupFile = Join-Path $BackupDir "${ScriptName}_Backup_${Timestamp}.reg"
$ServicesBackupFile = Join-Path $BackupDir "${ScriptName}_Services_${Timestamp}.json"

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}
#endregion

#region FUNCTIONS
function Write-Log {
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

function Test-TamperProtectionActive {
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.TamperProtection -in @(5, 1)) {
            return $true
        }
        
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($status.IsTamperProtected) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

function Create-SystemRestorePoint {
    try {
        Write-Log "Creating System Restore Point: $RestorePointName"
        
        # Enable System Restore if disabled
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        
        Checkpoint-Computer -Description $RestorePointName -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log "System Restore Point created successfully" -Type "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to create System Restore Point: $_" -Type "ERROR"
        return $false
    }
}

function Backup-DefenderServices {
    try {
        Write-Log "Backing up Windows Defender services state..."
        
        $services = @('WinDefend', 'SecurityHealthService', 'Sense', 'WdNisSvc', 'WdNisDrv', 'WdFilter', 'WdBoot')
        $serviceStates = @{}
        
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $serviceStates[$serviceName] = @{
                    Status = $service.Status.ToString()
                    StartType = $service.StartType.ToString()
                }
            }
        }
        
        $serviceStates | ConvertTo-Json | Out-File $ServicesBackupFile -Encoding UTF8
        Write-Log "Services backup created: $ServicesBackupFile" -Type "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to backup services: $_" -Type "WARNING"
        return $false
    }
}

function Create-RegistryBackup {
    try {
        Write-Log "Creating registry backup..."
        
        $regPaths = @(
            "HKLM\SOFTWARE\Microsoft\Windows Defender",
            "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            "HKCU\Software\Microsoft\Windows Defender",
            "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend",
            "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService",
            "HKLM\SYSTEM\CurrentControlSet\Services\Sense"
        )
        
        $backupContent = "Windows Registry Editor Version 5.00`r`n`r`n"
        
        foreach ($regPath in $regPaths) {
            $tempFile = Join-Path $env:TEMP "temp_$(Get-Random).reg"
            $result = reg export $regPath $tempFile /y 2>$null
            
            if ($LASTEXITCODE -eq 0 -and (Test-Path $tempFile)) {
                $content = Get-Content $tempFile -Raw -Encoding Unicode
                $backupContent += $content + "`r`n"
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
        
        [System.IO.File]::WriteAllText($BackupFile, $backupContent, [System.Text.Encoding]::Unicode)
        Write-Log "Registry backup created: $BackupFile" -Type "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to create registry backup: $_" -Type "ERROR"
        return $false
    }
}

function Disable-DefenderServices {
    $results = @()
    $services = @(
        @{Name='WinDefend'; Display='Windows Defender Antivirus Service'},
        @{Name='SecurityHealthService'; Display='Windows Security Service'},
        @{Name='Sense'; Display='Windows Defender Advanced Threat Protection'},
        @{Name='WdNisSvc'; Display='Windows Defender Network Inspection'}
    )
    
    foreach ($svc in $services) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                $results += @{Service=$svc.Display; Success=$true}
                Write-Log "? Disabled: $($svc.Display)" -Type "SUCCESS"
            }
        }
        catch {
            $results += @{Service=$svc.Display; Success=$false}
            Write-Log "? Failed: $($svc.Display) - $_" -Type "WARNING"
        }
    }
    
    return $results
}

function Disable-DefenderScheduledTasks {
    $results = @()
    $taskPaths = @(
        '\Microsoft\Windows\Windows Defender\*',
        '\Microsoft\Windows\Windows Defender\Windows Defender*'
    )
    
    foreach ($taskPath in $taskPaths) {
        try {
            $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                $results += @{Task=$task.TaskName; Success=$true}
                Write-Log "? Disabled task: $($task.TaskName)" -Type "SUCCESS"
            }
        }
        catch {
            Write-Log "? Failed to disable tasks in $taskPath" -Type "WARNING"
        }
    }
    
    return $results
}

function Disable-TamperProtectionRegistry {
    $results = @()
    
    # Method 1: HKLM Features - Primary method
    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "TamperProtection" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "TamperProtectionSource" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
        $results += @{Method="HKLM Features\TamperProtection"; Success=$true}
        Write-Log "? HKLM\...\Features\TamperProtection = 0" -Type "SUCCESS"
    }
    catch {
        $results += @{Method="HKLM Features\TamperProtection"; Success=$false}
        Write-Log "? HKLM Features failed: $_" -Type "ERROR"
    }
    
    # Method 2: HKCU DisableAntiTamper
    try {
        $path = "HKCU:\Software\Microsoft\Windows Defender"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DisableAntiTamper" -Value 1 -Type DWord -Force
        $results += @{Method="HKCU DisableAntiTamper"; Success=$true}
        Write-Log "? HKCU\...\DisableAntiTamper = 1" -Type "SUCCESS"
    }
    catch {
        $results += @{Method="HKCU DisableAntiTamper"; Success=$false}
    }
    
    # Method 3: HKCU Features
    try {
        $path = "HKCU:\Software\Microsoft\Windows Defender\Features"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "TamperProtection" -Value 0 -Type DWord -Force
        $results += @{Method="HKCU Features\TamperProtection"; Success=$true}
        Write-Log "? HKCU\...\Features\TamperProtection = 0" -Type "SUCCESS"
    }
    catch {
        $results += @{Method="HKCU Features\TamperProtection"; Success=$false}
    }
    
    # Method 4: Group Policy
    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DisableAntiTamper" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        $results += @{Method="Group Policy"; Success=$true}
        Write-Log "? Group Policy settings applied" -Type "SUCCESS"
    }
    catch {
        $results += @{Method="Group Policy"; Success=$false}
    }
    
    # Method 5: Real-Time Protection
    try {
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $path -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
        $results += @{Method="Real-Time Protection"; Success=$true}
        Write-Log "? Real-Time Protection disabled" -Type "SUCCESS"
    }
    catch {
        $results += @{Method="Real-Time Protection"; Success=$false}
    }
    
    return $results
}
#endregion

#region MAIN EXECUTION
Clear-Host
Write-Host "`n=========================================================" -ForegroundColor Cyan
Write-Host "    WINDOWS DEFENDER TAMPER PROTECTION DISABLER" -ForegroundColor Cyan
Write-Host "          Windows 11 Pro - Aggressive Mode" -ForegroundColor Cyan
Write-Host "=========================================================`n" -ForegroundColor Cyan

# Pre-check
Write-Log "Checking current Tamper Protection status..."
$isTamperActive = Test-TamperProtectionActive
if ($isTamperActive) {
    Write-Log "Tamper Protection is ACTIVE - proceeding with disable" -Type "WARNING"
} else {
    Write-Log "Tamper Protection appears INACTIVE" -Type "SUCCESS"
    $continue = Read-Host "`nContinue anyway? (y/n)"
    if ($continue -notmatch '^[yY]') { exit 0 }
}

# Step 1: Create System Restore Point
Write-Host "`n[STEP 1] Creating System Restore Point..." -ForegroundColor Cyan
if (-not (Create-SystemRestorePoint)) {
    $continue = Read-Host "Continue without restore point? (y/n)"
    if ($continue -notmatch '^[yY]') { exit 1 }
}

# Step 2: Create backups
Write-Host "`n[STEP 2] Creating backups..." -ForegroundColor Cyan
Backup-DefenderServices | Out-Null
Create-RegistryBackup | Out-Null

# Step 3: Disable via Registry
Write-Host "`n[STEP 3] Disabling Tamper Protection via Registry..." -ForegroundColor Cyan
$regResults = Disable-TamperProtectionRegistry

# Step 4: Disable Services
Write-Host "`n[STEP 4] Disabling Windows Defender Services..." -ForegroundColor Cyan
$serviceResults = Disable-DefenderServices

# Step 5: Disable Scheduled Tasks
Write-Host "`n[STEP 5] Disabling Defender Scheduled Tasks..." -ForegroundColor Cyan
$taskResults = Disable-DefenderScheduledTasks

# Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "OPERATION COMPLETED" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "Registry methods: $($regResults.Count) executed"
Write-Host "Services disabled: $(($serviceResults | Where-Object Success).Count)"
Write-Host "Tasks disabled: $(($taskResults | Where-Object Success).Count)"
Write-Host "`nBackup files created:"
Write-Host "  - $BackupFile" -ForegroundColor Gray
Write-Host "  - $ServicesBackupFile" -ForegroundColor Gray
Write-Host "`n??  RESTART REQUIRED for changes to take full effect" -ForegroundColor Yellow
Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
#endregion