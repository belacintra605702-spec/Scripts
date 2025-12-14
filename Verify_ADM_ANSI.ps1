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

# Verify_ADM_ANSI.ps1
# Verification of ANSI encoding and administrator privileges for scripts.

function Get-FileEncoding {
    param([string]$filePath)
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        
        if ($bytes.Length -eq 0) {
            return "EMPTY"
        }
        
        # Check for UTF-8 BOM
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            return "UTF-8-BOM"
        }
        
        # Check for UTF-16 LE BOM
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            return "UTF-16LE"
        }
        
        # Check for UTF-16 BE BOM
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            return "UTF-16BE"
        }
        
        # Check for UTF-32 LE BOM
        if ($bytes.Length -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
            return "UTF-32LE"
        }
        
        # Check for UTF-32 BE BOM
        if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
            return "UTF-32BE"
        }
        
        # Detect UTF-8 without BOM by checking for invalid byte sequences
        $isUTF8 = $true
        $hasNonASCII = $false
        
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $byte = $bytes[$i]
            
            # ASCII range (0-127) is valid in both ANSI and UTF-8
            if ($byte -le 0x7F) {
                continue
            }
            
            $hasNonASCII = $true
            
            # Check for valid UTF-8 multi-byte sequences
            if ($byte -ge 0xC2 -and $byte -le 0xDF) {
                # 2-byte sequence
                if ($i + 1 -ge $bytes.Length -or ($bytes[$i + 1] -lt 0x80 -or $bytes[$i + 1] -gt 0xBF)) {
                    $isUTF8 = $false
                    break
                }
                $i++
            }
            elseif ($byte -ge 0xE0 -and $byte -le 0xEF) {
                # 3-byte sequence
                if ($i + 2 -ge $bytes.Length -or 
                    ($bytes[$i + 1] -lt 0x80 -or $bytes[$i + 1] -gt 0xBF) -or
                    ($bytes[$i + 2] -lt 0x80 -or $bytes[$i + 2] -gt 0xBF)) {
                    $isUTF8 = $false
                    break
                }
                $i += 2
            }
            elseif ($byte -ge 0xF0 -and $byte -le 0xF4) {
                # 4-byte sequence
                if ($i + 3 -ge $bytes.Length -or 
                    ($bytes[$i + 1] -lt 0x80 -or $bytes[$i + 1] -gt 0xBF) -or
                    ($bytes[$i + 2] -lt 0x80 -or $bytes[$i + 2] -gt 0xBF) -or
                    ($bytes[$i + 3] -lt 0x80 -or $bytes[$i + 3] -gt 0xBF)) {
                    $isUTF8 = $false
                    break
                }
                $i += 3
            }
            else {
                # Invalid UTF-8 starting byte, likely ANSI
                $isUTF8 = $false
                break
            }
        }
        
        if ($isUTF8 -and $hasNonASCII) {
            return "UTF-8"
        }
        
        return "ANSI"
    }
    catch {
        Write-Warning "Error reading file $filePath : $_"
        return "ERROR"
    }
}

function Test-AdminPrivileges {
    param(
        [string]$filePath,
        [string]$extension,
        [string]$encoding
    )
    
    # If encoding is not readable, we cannot check admin privileges reliably
    if ($encoding -notin @("ANSI", "UTF-8", "UTF-8-BOM")) {
        return $false
    }
    
    try {
        # Read only first 30 lines to check for elevation block
        $lines = Get-Content $filePath -TotalCount 30 -ErrorAction Stop
        $content = $lines -join "`n"
        
        if ($extension -eq '.ps1') {
            # Check for new standard elevation marker
            return $content -match '# ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION'
        }
        elseif ($extension -eq '.bat') {
            # Check for batch elevation marker
            return $content -match 'REM ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION'
        }
        
        return $false
    }
    catch {
        Write-Warning "Error checking admin privileges for $filePath : $_"
        return $false
    }
}

# Main script execution
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath
$convertScriptPath = Join-Path $scriptDir "Convert_ADM_ANSI.ps1"

# Get script names to exclude - Use actual filenames
$thisScriptName = Split-Path -Leaf $scriptPath
$convertScriptName = "Convert_ADM_ANSI.ps1"

$nonANSIFiles = @()
$nonAdminFiles = @()
$totalFiles = 0
$rootFiles = 0
$subfolderFiles = 0

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Script Verification Tool" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scanning directory: $scriptDir" -ForegroundColor White
Write-Host "Checking for ANSI encoding and administrator privileges..." -ForegroundColor White
Write-Host ""

# Step 1: Check files in ROOT directory only (excluding these two scripts)
Write-Host "--- Checking ROOT directory ---" -ForegroundColor Cyan
$rootFilesCollection = @()
$rootFilesCollection += Get-ChildItem -Path "$scriptDir\*.ps1" -File -ErrorAction SilentlyContinue
$rootFilesCollection += Get-ChildItem -Path "$scriptDir\*.bat" -File -ErrorAction SilentlyContinue
$rootFilesCollection = $rootFilesCollection | Where-Object { $_.Name -ne $thisScriptName -and $_.Name -ne $convertScriptName }

foreach ($file in $rootFilesCollection) {
    $totalFiles++
    $rootFiles++
    
    # Check encoding FIRST
    $encoding = Get-FileEncoding $file.FullName
    $hasEncodingIssue = $false
    
    if ($encoding -eq "ERROR") {
        Write-Host "[ROOT] $($file.Name)" -ForegroundColor Red
        Write-Host "       - ERROR: Cannot read file" -ForegroundColor Red
        continue
    }
    
    if ($encoding -ne "ANSI") {
        $nonANSIFiles += $file.FullName
        $hasEncodingIssue = $true
    }
    
    # Check for admin privileges (pass encoding info)
    $hasAdminPriv = Test-AdminPrivileges -filePath $file.FullName -extension $file.Extension -encoding $encoding
    $hasAdminIssue = $false
    if (-not $hasAdminPriv) {
        $nonAdminFiles += $file.FullName
        $hasAdminIssue = $true
    }
    
    # Display issues
    if ($hasEncodingIssue -or $hasAdminIssue) {
        Write-Host "[ROOT] $($file.Name)" -ForegroundColor Yellow
        if ($hasEncodingIssue) {
            Write-Host "       - Encoding: $encoding (Expected: ANSI)" -ForegroundColor Gray
        }
        if ($hasAdminIssue) {
            Write-Host "       - Missing administrative privileges block" -ForegroundColor Gray
        }
    }
}

# Step 2: Check files in ALL SUBFOLDERS recursively
Write-Host ""
Write-Host "--- Checking SUBFOLDERS (recursive) ---" -ForegroundColor Cyan
$subfolderFilesCollection = Get-ChildItem -Path $scriptDir -Include *.ps1, *.bat -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { 
        # Exclude files in root directory
        (Split-Path -Parent $_.FullName) -ne $scriptDir
    }

foreach ($file in $subfolderFilesCollection) {
    $totalFiles++
    $subfolderFiles++
    $relativePath = $file.FullName.Replace($scriptDir, ".")
    
    # Check encoding FIRST
    $encoding = Get-FileEncoding $file.FullName
    $hasEncodingIssue = $false
    
    if ($encoding -eq "ERROR") {
        Write-Host "[SUBFOLDER] $relativePath" -ForegroundColor Red
        Write-Host "            - ERROR: Cannot read file" -ForegroundColor Red
        continue
    }
    
    if ($encoding -ne "ANSI") {
        $nonANSIFiles += $file.FullName
        $hasEncodingIssue = $true
    }
    
    # Check for admin privileges (pass encoding info)
    $hasAdminPriv = Test-AdminPrivileges -filePath $file.FullName -extension $file.Extension -encoding $encoding
    $hasAdminIssue = $false
    if (-not $hasAdminPriv) {
        $nonAdminFiles += $file.FullName
        $hasAdminIssue = $true
    }
    
    # Display issues
    if ($hasEncodingIssue -or $hasAdminIssue) {
        Write-Host "[SUBFOLDER] $relativePath" -ForegroundColor Yellow
        if ($hasEncodingIssue) {
            Write-Host "            - Encoding: $encoding (Expected: ANSI)" -ForegroundColor Gray
        }
        if ($hasAdminIssue) {
            Write-Host "            - Missing administrative privileges block" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Verification Summary" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Total files scanned: $totalFiles" -ForegroundColor White
Write-Host "  - Root directory: $rootFiles" -ForegroundColor White
Write-Host "  - Subfolders: $subfolderFiles" -ForegroundColor White

if ($nonANSIFiles.Count -eq 0 -and $nonAdminFiles.Count -eq 0) {
    Write-Host ""
    Write-Host "SUCCESS: All scripts are properly configured!" -ForegroundColor Green
    Write-Host "- All files are ANSI encoded" -ForegroundColor Green
    Write-Host "- All files have administrative privileges block" -ForegroundColor Green
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

# Summary of issues found
Write-Host ""
Write-Host "ISSUES FOUND:" -ForegroundColor Red

if ($nonANSIFiles.Count -gt 0) {
    Write-Host "- Files with non-ANSI encoding: $($nonANSIFiles.Count)" -ForegroundColor Yellow
}

if ($nonAdminFiles.Count -gt 0) {
    Write-Host "- Files missing administrative privileges block: $($nonAdminFiles.Count)" -ForegroundColor Yellow
}

Write-Host ""

# Check if conversion script exists
if (-not (Test-Path $convertScriptPath)) {
    Write-Host "WARNING: Convert_ADM_ANSI.ps1 not found at: $convertScriptPath" -ForegroundColor Red
    Write-Host "Please ensure the conversion script exists to fix these issues." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Ask user to run conversion
do {
    $userResponse = Read-Host "Do you want to run Convert_ADM_ANSI.ps1 to fix these issues? (Y/N)"
    $userResponse = $userResponse.Trim().ToUpper()
    
    if ($userResponse -eq 'Y') {
        Write-Host ""
        Write-Host "Starting Convert_ADM_ANSI.ps1..." -ForegroundColor Green
        Write-Host ""
        
        try {
            & $convertScriptPath
            Write-Host ""
            Write-Host "Conversion completed. Please review the results above." -ForegroundColor Green
        }
        catch {
            Write-Host ""
            Write-Host "ERROR: Failed to run Convert_ADM_ANSI.ps1" -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
        }
        break
    }
    elseif ($userResponse -eq 'N') {
        Write-Host ""
        Write-Host "Conversion cancelled." -ForegroundColor Yellow
        Write-Host "You can run Convert_ADM_ANSI.ps1 manually to fix the issues." -ForegroundColor Yellow
        break
    }
    else {
        Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
    }
} while ($true)

Write-Host ""
Read-Host "Press Enter to exit"