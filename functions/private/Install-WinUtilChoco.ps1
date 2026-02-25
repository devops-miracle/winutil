function Install-WinUtilChoco {

    <#

    .SYNOPSIS
        Installs Chocolatey if it is not already installed
    
    .NOTES
        SECURITY WARNING: This function downloads and executes remote code without integrity verification.
        This is a known security vulnerability (CWE-494: Download of Code Without Integrity Check).
        
        Recommended improvements:
        1. Implement SHA-256 hash verification of downloaded script
        2. Verify digital signature of the install script
        3. Use HTTPS certificate pinning
        4. Add comprehensive audit logging
        
        See docs/SECURITY_ANALYSIS.md for detailed security assessment and remediation guide.

    #>
    if ((Test-WinUtilPackageManager -choco) -eq "installed") {
        return
    }

    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "SECURITY NOTICE" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "About to download and execute Chocolatey installer from:" -ForegroundColor Yellow
    Write-Host "https://community.chocolatey.org/install.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Note: This script is downloaded without integrity verification." -ForegroundColor Yellow
    Write-Host "For enhanced security, consider manual installation with hash verification." -ForegroundColor Yellow
    Write-Host "See: https://docs.chocolatey.org/en-us/choco/setup#more-install-options" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    
    # Log security-sensitive operation
    if (Get-Command Write-WinUtilLog -ErrorAction SilentlyContinue) {
        Write-WinUtilLog -Level Security -Message "Downloading Chocolatey installer without integrity verification" -Component "Chocolatey"
    }
    
    Write-Host "Installing Chocolatey..." -ForegroundColor Green
    
    # SECURITY VULNERABILITY: Remote code execution without verification
    # TODO: Replace with Invoke-WinUtilSecureDownload (see SECURITY_REMEDIATION_GUIDE.md)
    Invoke-WebRequest -Uri https://community.chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression
    
    if (Get-Command Write-WinUtilLog -ErrorAction SilentlyContinue) {
        Write-WinUtilLog -Level Information -Message "Chocolatey installation completed" -Component "Chocolatey"
    }
}
