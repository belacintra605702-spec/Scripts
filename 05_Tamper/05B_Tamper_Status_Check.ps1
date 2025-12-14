#requires -RunAsAdministrator
#requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive Tamper Protection status verification
.DESCRIPTION
    Checks all registry keys, services, and scheduled tasks related to Tamper Protection
.NOTES
    Windows 11 Pro - Enhanced verification
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

#region FUNCTIONS
function Get-ColorForStatus {
    param([bool]$IsDisabled)
    return if ($IsDisabled) { "Green" } else { "Red" }
}

function Check-RegistryValues {
    Write-Host "`n[REGISTRY CHECKS]" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan
    
    $checks = @()
    
    # Check 1: HKLM Features\TamperProtection (Primary)
    try {
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        $isDisabled = ($null -ne $val -and $val.TamperProtection -eq 0)
        $checks += @{Name="HKLM Features\TamperProtection"; Disabled=$isDisabled; Value=if($val){$val.TamperProtection}else{"Not set"}}
        Write-Host "  HKLM\...\Features\TamperProtection: " -NoNewline
        Write-Host "$(if($isDisabled){'DISABLED (0)'}else{'ENABLED/Not set'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
    }
    catch {
        Write-Host "  HKLM\...\Features\TamperProtection: Error checking" -ForegroundColor Yellow
    }
    
    # Check 2: HKCU DisableAntiTamper
    try {
        $val = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Defender" -Name "DisableAntiTamper" -ErrorAction SilentlyContinue
        $isDisabled = ($null -ne $val -and $val.DisableAntiTamper -eq 1)
        $checks += @{Name="HKCU DisableAntiTamper"; Disabled=$isDisabled; Value=if($val){$val.DisableAntiTamper}else{"Not set"}}
        Write-Host "  HKCU\...\DisableAntiTamper: " -NoNewline
        Write-Host "$(if($isDisabled){'DISABLED (1)'}else{'ENABLED/Not set'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
    }
    catch {
        Write-Host "  HKCU\...\DisableAntiTamper: Error checking" -ForegroundColor Yellow
    }
    
    # Check 3: HKCU Features\TamperProtection
    try {
        $val = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction SilentlyContinue
        $isDisabled = ($null -ne $val -and $val.TamperProtection -eq 0)
        $checks += @{Name="HKCU Features\TamperProtection"; Disabled=$isDisabled; Value=if($val){$val.TamperProtection}else{"Not set"}}
        Write-Host "  HKCU\...\Features\TamperProtection: " -NoNewline
        Write-Host "$(if($isDisabled){'DISABLED (0)'}else{'ENABLED/Not set'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
    }
    catch {
        Write-Host "  HKCU\...\Features\TamperProtection: Error checking" -ForegroundColor Yellow
    }
    
    # Check 4: Group Policy DisableAntiSpyware
    try {
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        $isDisabled = ($null -ne $val -and $val.DisableAntiSpyware -eq 1)
        $checks += @{Name="Group Policy DisableAntiSpyware"; Disabled=$isDisabled; Value=if($val){$val.DisableAntiSpyware}else{"Not set"}}
        Write-Host "  HKLM\Policies\...\DisableAntiSpyware: " -NoNewline
        Write-Host "$(if($isDisabled){'DISABLED (1)'}else{'ENABLED/Not set'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
    }
    catch {
        Write-Host "  HKLM\Policies\...\DisableAntiSpyware: Error checking" -ForegroundColor Yellow
    }
    
    # Check 5: Real-Time Protection
    try {
        $val = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
        $isDisabled = ($null -ne $val -and $val.DisableRealtimeMonitoring -eq 1)
        $checks += @{Name="Real-Time Monitoring"; Disabled=$isDisabled; Value=if($val){$val.DisableRealtimeMonitoring}else{"Not set"}}
        Write-Host "  Real-Time Monitoring: " -NoNewline
        Write-Host "$(if($isDisabled){'DISABLED (1)'}else{'ENABLED/Not set'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
    }
    catch {
        Write-Host "  Real-Time Monitoring: Error checking" -ForegroundColor Yellow
    }
    
    # Check 6: PowerShell Get-MpComputerStatus
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($mpStatus) {
                $isDisabled = ($mpStatus.IsTamperProtected -eq $false)
                $checks += @{Name="PowerShell IsTamperProtected"; Disabled=$isDisabled; Value=$mpStatus.IsTamperProtected}
                Write-Host "  PowerShell IsTamperProtected: " -NoNewline
                Write-Host "$(if($isDisabled){'DISABLED (False)'}else{'ENABLED (True)'})" -ForegroundColor $(Get-ColorForStatus $isDisabled)
            }
        }
    }
    catch {
        Write-Host "  PowerShell IsTamperProtected: Not available" -ForegroundColor Gray
    }
    
    return $checks
}

function Check-DefenderServices {
    Write-Host "`n[SERVICES CHECK]" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan
    
    $serviceChecks = @()
    $services = @(
        @{Name='WinDefend'; Display='Windows Defender Antivirus'},
        @{Name='SecurityHealthService'; Display='Windows Security Service'},
        @{Name='Sense'; Display='Windows Defender ATP'},
        @{Name='WdNisSvc'; Display='Network Inspection Service'}
    )
    
    foreach ($svc in $services) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
                $isDisabled = ($service.Status -eq 'Stopped' -and $service.StartType -eq 'Disabled')
                $serviceChecks += @{Name=$svc.Display; Disabled=$isDisabled}
                Write-Host "  $($svc.Display): " -NoNewline
                Write-Host "$($service.Status) / $($service.StartType)" -ForegroundColor $(Get-ColorForStatus $isDisabled)
            } else {
                Write-Host "  $($svc.Display): Not found" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "  $($svc.Display): Error checking" -ForegroundColor Yellow
        }
    }
    
    return $serviceChecks
}

function Check-DefenderTasks {
    Write-Host "`n[SCHEDULED TASKS CHECK]" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan
    
    $taskChecks = @()
    
    try {
        $tasks = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\*' -ErrorAction SilentlyContinue
        if ($tasks) {
            foreach ($task in $tasks) {
                $isDisabled = ($task.State -eq 'Disabled')
                $taskChecks += @{Name=$task.TaskName; Disabled=$isDisabled}
                Write-Host "  $($task.TaskName): " -NoNewline
                Write-Host "$($task.State)" -ForegroundColor $(Get-ColorForStatus $isDisabled)
            }
        } else {
            Write-Host "  No Defender tasks found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error checking scheduled tasks" -ForegroundColor Yellow
    }
    
    return $taskChecks
}
#endregion

#region MAIN EXECUTION
Clear-Host
Write-Host "`n=========================================================" -ForegroundColor Cyan
Write-Host "       TAMPER PROTECTION STATUS VERIFICATION" -ForegroundColor Cyan
Write-Host "            Comprehensive Check - Windows 11" -ForegroundColor Cyan
Write-Host "=========================================================`n" -ForegroundColor Cyan

# Check Registry
$regChecks = Check-RegistryValues

# Check Services
$serviceChecks = Check-DefenderServices

# Check Scheduled Tasks
$taskChecks = Check-DefenderTasks

# Calculate Summary
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "[SUMMARY]" -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

$totalChecks = 0
$disabledCount = 0

if ($regChecks.Count -gt 0) {
    $regDisabled = ($regChecks | Where-Object { $_.Disabled }).Count
    $disabledCount += $regDisabled
    $totalChecks += $regChecks.Count
    Write-Host "`nRegistry: $regDisabled of $($regChecks.Count) disabled"
}

if ($serviceChecks.Count -gt 0) {
    $svcDisabled = ($serviceChecks | Where-Object { $_.Disabled }).Count
    $disabledCount += $svcDisabled
    $totalChecks += $serviceChecks.Count
    Write-Host "Services: $svcDisabled of $($serviceChecks.Count) disabled"
}

if ($taskChecks.Count -gt 0) {
    $taskDisabled = ($taskChecks | Where-Object { $_.Disabled }).Count
    $disabledCount += $taskDisabled
    $totalChecks += $taskChecks.Count
    Write-Host "Scheduled Tasks: $taskDisabled of $($taskChecks.Count) disabled"
}

if ($totalChecks -gt 0) {
    $percentage = [math]::Round(($disabledCount / $totalChecks) * 100)
    
    Write-Host "`nOVERALL: $disabledCount of $totalChecks checks show disabled ($percentage%)" -ForegroundColor White
    Write-Host ("="*60) -ForegroundColor Cyan
    
    if ($percentage -eq 100) {
        Write-Host "`n? TAMPER PROTECTION IS 100% DISABLED" -ForegroundColor Green
    }
    elseif ($percentage -ge 80) {
        Write-Host "`n? TAMPER PROTECTION IS MOSTLY DISABLED ($percentage%)" -ForegroundColor Green
        Write-Host "  Some components may still be active" -ForegroundColor Yellow
    }
    elseif ($percentage -ge 50) {
        Write-Host "`n? TAMPER PROTECTION IS PARTIALLY DISABLED ($percentage%)" -ForegroundColor Yellow
        Write-Host "  Consider re-running 05A_Tamper_Disable.ps1" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n? TAMPER PROTECTION IS MOSTLY ENABLED ($percentage%)" -ForegroundColor Red
        Write-Host "  Run 05A_Tamper_Disable.ps1 to disable it" -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n? No checks could be performed" -ForegroundColor Red
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
#endregion