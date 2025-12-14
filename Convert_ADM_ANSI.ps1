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

# Convert_ADM_ANSI.ps1
# Converts PowerShell and batch scripts to ANSI encoding and ensures administrator privileges.

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
        Write-Warning "Error reading file encoding for $filePath : $_"
        return "ERROR"
    }
}

function Test-HasElevationBlock {
    param(
        [string]$filePath,
        [string]$extension,
        [string]$encoding
    )
    
    # If encoding is not readable, we cannot check reliably
    if ($encoding -notin @("ANSI", "UTF-8", "UTF-8-BOM")) {
        return $false
    }
    
    try {
        # Read only first 30 lines to check for elevation marker
        $lines = Get-Content $filePath -TotalCount 30 -ErrorAction Stop
        $content = $lines -join "`n"
        
        if ($extension -eq '.ps1') {
            return $content -match '# ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION'
        }
        elseif ($extension -eq '.bat') {
            return $content -match 'REM ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION'
        }
        
        return $false
    }
    catch {
        Write-Warning "Error checking elevation block for $filePath : $_"
        return $false
    }
}

function Convert-ToANSI {
    param(
        [string]$filePath,
        [string]$currentEncoding
    )
    
    try {
        # For UTF-16 and UTF-32, we need to specify the encoding when reading
        $content = $null
        
        switch ($currentEncoding) {
            "UTF-8-BOM" {
                $content = Get-Content $filePath -Raw -Encoding UTF8
            }
            "UTF-8" {
                $content = Get-Content $filePath -Raw -Encoding UTF8
            }
            "UTF-16LE" {
                $content = Get-Content $filePath -Raw -Encoding Unicode
            }
            "UTF-16BE" {
                $content = Get-Content $filePath -Raw -Encoding BigEndianUnicode
            }
            "UTF-32LE" {
                $content = Get-Content $filePath -Raw -Encoding UTF32
            }
            "UTF-32BE" {
                # UTF-32 BE is not directly supported, read as bytes and convert
                $bytes = [System.IO.File]::ReadAllBytes($filePath)
                $content = [System.Text.Encoding]::GetEncoding("UTF-32BE").GetString($bytes)
            }
            default {
                $content = Get-Content $filePath -Raw
            }
        }
        
        if ($null -eq $content) {
            return $false
        }
        
        # Convert to ANSI (Default encoding in Windows)
        [System.IO.File]::WriteAllText($filePath, $content, [System.Text.Encoding]::Default)
        
        return $true
    }
    catch {
        Write-Warning "Error converting $filePath to ANSI: $_"
        return $false
    }
}

function Add-ElevationBlock {
    param(
        [string]$filePath,
        [string]$extension,
        [string]$currentEncoding
    )
    
    try {
        # Read existing content with proper encoding
        $existingContent = $null
        
        switch ($currentEncoding) {
            "UTF-8-BOM" {
                $existingContent = Get-Content $filePath -Raw -Encoding UTF8
            }
            "UTF-8" {
                $existingContent = Get-Content $filePath -Raw -Encoding UTF8
            }
            "UTF-16LE" {
                $existingContent = Get-Content $filePath -Raw -Encoding Unicode
            }
            "UTF-16BE" {
                $existingContent = Get-Content $filePath -Raw -Encoding BigEndianUnicode
            }
            "UTF-32LE" {
                $existingContent = Get-Content $filePath -Raw -Encoding UTF32
            }
            "UTF-32BE" {
                $bytes = [System.IO.File]::ReadAllBytes($filePath)
                $existingContent = [System.Text.Encoding]::GetEncoding("UTF-32BE").GetString($bytes)
            }
            default {
                $existingContent = Get-Content $filePath -Raw
            }
        }
        
        if ($null -eq $existingContent) {
            return $false
        }
        
        # Remove any leading blank lines
        $existingContent = $existingContent -replace '^\s+', ''
        
        if ($extension -eq ".ps1") {
            $elevationCode = @"
# =============================================================================
# ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION
# =============================================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "``nAdministrative privileges required..." -ForegroundColor Yellow
    Write-Host "Requesting elevation via UAC..." -ForegroundColor Gray
    
    try {
        `$arguments = "-NoProfile -ExecutionPolicy Bypass -File ```"`$PSCommandPath```""
        if (`$args.Count -gt 0) {
            `$arguments += " " + (`$args -join " ")
        }
        
        Start-Process powershell.exe -ArgumentList `$arguments -Verb RunAs
        exit
    }
    catch {
        Write-Host "``nERROR: Failed to elevate privileges!" -ForegroundColor Red
        Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        Write-Host "Error details: `$_" -ForegroundColor Gray
        pause
        exit 1
    }
}

# Verification that we're running as admin (after potential elevation)
Write-Host "``nRunning with administrative privileges..." -ForegroundColor Green
# =============================================================================

"@
            $newContent = $elevationCode + $existingContent
        }
        elseif ($extension -eq ".bat") {
            $elevationCode = @"
@echo off
REM =============================================================================
REM ADMINISTRATIVE PRIVILEGES - AUTO ELEVATION
REM =============================================================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo Administrative privileges required...
    echo Requesting elevation via UAC...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
    exit /b
)

echo.
echo Running with administrative privileges...
REM =============================================================================

"@
            $newContent = $elevationCode + $existingContent
        }
        else {
            return $false
        }
        
        # Write with ANSI encoding
        [System.IO.File]::WriteAllText($filePath, $newContent, [System.Text.Encoding]::Default)
        
        return $true
    }
    catch {
        Write-Warning "Error adding elevation block to $filePath : $_"
        return $false
    }
}

# Main script execution
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path -Parent $scriptPath

# Get script names to exclude - Use actual filenames
$thisScriptName = Split-Path -Leaf $scriptPath
$verifyScriptName = "Verify_ADM_ANSI.ps1"

$filesConverted = 0
$filesElevationAdded = 0
$filesBothFixed = 0
$filesSkipped = 0
$filesError = 0
$totalFiles = 0
$rootFiles = 0
$subfolderFiles = 0

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Script Conversion Tool" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scanning directory: $scriptDir" -ForegroundColor White
Write-Host "Converting to ANSI and ensuring administrative privileges block..." -ForegroundColor White
Write-Host ""

# Step 1: Convert files in ROOT directory only (excluding these two scripts)
Write-Host "--- Processing ROOT directory ---" -ForegroundColor Cyan
$rootFilesCollection = @()
$rootFilesCollection += Get-ChildItem -Path "$scriptDir\*.ps1" -File -ErrorAction SilentlyContinue
$rootFilesCollection += Get-ChildItem -Path "$scriptDir\*.bat" -File -ErrorAction SilentlyContinue
$rootFilesCollection = $rootFilesCollection | Where-Object { $_.Name -ne $thisScriptName -and $_.Name -ne $verifyScriptName }

foreach ($file in $rootFilesCollection) {
    $totalFiles++
    $rootFiles++
    $changes = @()
    $needsEncodingFix = $false
    $needsElevationBlock = $false
    
    # Check encoding FIRST
    $encoding = Get-FileEncoding $file.FullName
    if ($encoding -eq "ERROR") {
        Write-Host "[ERROR - ROOT] $($file.Name) - Could not read file" -ForegroundColor Red
        $filesError++
        continue
    }
    
    if ($encoding -ne "ANSI") {
        $needsEncodingFix = $true
    }
    
    # Check if has our elevation block (pass encoding info)
    $hasElevationBlock = Test-HasElevationBlock -filePath $file.FullName -extension $file.Extension -encoding $encoding
    if (-not $hasElevationBlock) {
        $needsElevationBlock = $true
    }
    
    # Skip if no changes needed
    if (-not $needsEncodingFix -and -not $needsElevationBlock) {
        continue
    }
    
    # Apply fixes
    try {
        # Case 1: Both fixes needed
        if ($needsEncodingFix -and $needsElevationBlock) {
            if (Add-ElevationBlock -filePath $file.FullName -extension $file.Extension -currentEncoding $encoding) {
                $changes += "Added administrative privileges block"
                $changes += "Converted to ANSI (was $encoding)"
                $filesBothFixed++
            }
            else {
                Write-Host "[ERROR - ROOT] $($file.Name) - Conversion failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        # Case 2: Only encoding fix needed
        elseif ($needsEncodingFix) {
            if (Convert-ToANSI -filePath $file.FullName -currentEncoding $encoding) {
                $changes += "Converted to ANSI (was $encoding)"
                $filesConverted++
            }
            else {
                Write-Host "[ERROR - ROOT] $($file.Name) - Encoding conversion failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        # Case 3: Only elevation block needed
        elseif ($needsElevationBlock) {
            if (Add-ElevationBlock -filePath $file.FullName -extension $file.Extension -currentEncoding $encoding) {
                $changes += "Added administrative privileges block"
                $filesElevationAdded++
            }
            else {
                Write-Host "[ERROR - ROOT] $($file.Name) - Elevation block addition failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        
        if ($changes.Count -gt 0) {
            Write-Host "[FIXED - ROOT] $($file.Name)" -ForegroundColor Green
            Write-Host "               $($changes -join ' + ')" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[ERROR - ROOT] $($file.Name) - $_" -ForegroundColor Red
        $filesError++
    }
}

# Step 2: Convert files in ALL SUBFOLDERS recursively
Write-Host ""
Write-Host "--- Processing SUBFOLDERS (recursive) ---" -ForegroundColor Cyan
$subfolderFilesCollection = Get-ChildItem -Path $scriptDir -Include *.ps1, *.bat -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { 
        # Exclude files in root directory
        (Split-Path -Parent $_.FullName) -ne $scriptDir
    }

foreach ($file in $subfolderFilesCollection) {
    $totalFiles++
    $subfolderFiles++
    $relativePath = $file.FullName.Replace($scriptDir, ".")
    $changes = @()
    $needsEncodingFix = $false
    $needsElevationBlock = $false
    
    # Check encoding FIRST
    $encoding = Get-FileEncoding $file.FullName
    if ($encoding -eq "ERROR") {
        Write-Host "[ERROR - SUBFOLDER] $relativePath - Could not read file" -ForegroundColor Red
        $filesError++
        continue
    }
    
    if ($encoding -ne "ANSI") {
        $needsEncodingFix = $true
    }
    
    # Check if has our elevation block (pass encoding info)
    $hasElevationBlock = Test-HasElevationBlock -filePath $file.FullName -extension $file.Extension -encoding $encoding
    if (-not $hasElevationBlock) {
        $needsElevationBlock = $true
    }
    
    # Skip if no changes needed
    if (-not $needsEncodingFix -and -not $needsElevationBlock) {
        continue
    }
    
    # Apply fixes
    try {
        # Case 1: Both fixes needed
        if ($needsEncodingFix -and $needsElevationBlock) {
            if (Add-ElevationBlock -filePath $file.FullName -extension $file.Extension -currentEncoding $encoding) {
                $changes += "Added administrative privileges block"
                $changes += "Converted to ANSI (was $encoding)"
                $filesBothFixed++
            }
            else {
                Write-Host "[ERROR - SUBFOLDER] $relativePath - Conversion failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        # Case 2: Only encoding fix needed
        elseif ($needsEncodingFix) {
            if (Convert-ToANSI -filePath $file.FullName -currentEncoding $encoding) {
                $changes += "Converted to ANSI (was $encoding)"
                $filesConverted++
            }
            else {
                Write-Host "[ERROR - SUBFOLDER] $relativePath - Encoding conversion failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        # Case 3: Only elevation block needed
        elseif ($needsElevationBlock) {
            if (Add-ElevationBlock -filePath $file.FullName -extension $file.Extension -currentEncoding $encoding) {
                $changes += "Added administrative privileges block"
                $filesElevationAdded++
            }
            else {
                Write-Host "[ERROR - SUBFOLDER] $relativePath - Elevation block addition failed" -ForegroundColor Red
                $filesError++
                continue
            }
        }
        
        if ($changes.Count -gt 0) {
            Write-Host "[FIXED - SUBFOLDER] $relativePath" -ForegroundColor Green
            Write-Host "                    $($changes -join ' + ')" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[ERROR - SUBFOLDER] $relativePath - $_" -ForegroundColor Red
        $filesError++
    }
}

# Summary
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Conversion Summary" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Total files scanned: $totalFiles" -ForegroundColor White
Write-Host "  - Root directory: $rootFiles" -ForegroundColor White
Write-Host "  - Subfolders: $subfolderFiles" -ForegroundColor White
Write-Host ""
Write-Host "Files converted to ANSI only: $filesConverted" -ForegroundColor $(if ($filesConverted -gt 0) { "Green" } else { "Gray" })
Write-Host "Files with admin privileges added only: $filesElevationAdded" -ForegroundColor $(if ($filesElevationAdded -gt 0) { "Green" } else { "Gray" })
Write-Host "Files with both fixes applied: $filesBothFixed" -ForegroundColor $(if ($filesBothFixed -gt 0) { "Green" } else { "Gray" })
Write-Host "Files skipped: $filesSkipped" -ForegroundColor $(if ($filesSkipped -gt 0) { "Yellow" } else { "Gray" })
Write-Host "Files with errors: $filesError" -ForegroundColor $(if ($filesError -gt 0) { "Red" } else { "Gray" })
Write-Host ""

$totalFixed = $filesConverted + $filesElevationAdded + $filesBothFixed

if ($totalFixed -eq 0 -and $filesError -eq 0) {
    Write-Host "SUCCESS: All files were already correct!" -ForegroundColor Green
}
elseif ($totalFixed -gt 0 -and $filesError -eq 0) {
    Write-Host "SUCCESS: Conversion completed successfully!" -ForegroundColor Green
}
elseif ($filesError -gt 0) {
    Write-Host "WARNING: Conversion completed with some errors." -ForegroundColor Yellow
    Write-Host "Please review the errors above." -ForegroundColor Yellow
}

Write-Host ""
Read-Host "Press Enter to exit"