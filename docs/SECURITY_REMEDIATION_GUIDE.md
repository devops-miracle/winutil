# Security Remediation Implementation Guide
## Guía de Implementación de Remediación de Seguridad

This document provides specific code implementations for remediating the critical security vulnerabilities identified in the security analysis.

---

## Table of Contents

1. [Secure Download Function](#1-secure-download-function)
2. [Replace Invoke-Expression](#2-replace-invoke-expression)
3. [Registry Validation](#3-registry-validation)
4. [Audit Logging System](#4-audit-logging-system)
5. [JSON Schema Validation](#5-json-schema-validation)
6. [Digital Signature Verification](#6-digital-signature-verification)
7. [Rollback Mechanism](#7-rollback-mechanism)
8. [Rate Limiting](#8-rate-limiting)

---

## 1. Secure Download Function

### Problem
Currently: Downloads execute without hash verification
```powershell
Invoke-WebRequest -Uri $url | Invoke-Expression
```

### Solution: Implement hash-verified downloads

**File:** `functions/private/Invoke-WinUtilSecureDownload.ps1`

```powershell
function Invoke-WinUtilSecureDownload {
    <#
    .SYNOPSIS
        Securely downloads and verifies content from a URL
    
    .DESCRIPTION
        Downloads content from a URL and verifies its integrity using SHA256 hash.
        Optionally verifies digital signature if the content is a script.
    
    .PARAMETER Url
        The URL to download from
    
    .PARAMETER ExpectedHash
        The expected SHA256 hash of the downloaded content
    
    .PARAMETER VerifySignature
        If true, verifies the Authenticode signature of the downloaded script
    
    .PARAMETER OutputPath
        Optional path to save the downloaded content
    
    .EXAMPLE
        Invoke-WinUtilSecureDownload -Url "https://example.com/script.ps1" `
            -ExpectedHash "ABC123..." -VerifySignature
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,
        
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedHash,
        
        [Parameter()]
        [switch]$VerifySignature,
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [int]$MaxRetries = 3,
        
        [Parameter()]
        [int]$TimeoutSeconds = 30
    )
    
    try {
        Write-WinUtilLog -Level Information -Message "Starting secure download from: $Url" -Component "SecureDownload"
        
        # Download content with retry logic
        $retryCount = 0
        $downloaded = $false
        $content = $null
        
        while (-not $downloaded -and $retryCount -lt $MaxRetries) {
            try {
                $content = Invoke-WebRequest -Uri $Url `
                    -UseBasicParsing `
                    -TimeoutSec $TimeoutSeconds `
                    -UserAgent "WinUtil/1.0 (Secure)" `
                    -ErrorAction Stop
                
                $downloaded = $true
            }
            catch {
                $retryCount++
                if ($retryCount -ge $MaxRetries) {
                    throw "Failed to download after $MaxRetries attempts: $_"
                }
                Write-WinUtilLog -Level Warning -Message "Download attempt $retryCount failed, retrying..." -Component "SecureDownload"
                Start-Sleep -Seconds (2 * $retryCount)
            }
        }
        
        # Verify hash
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($content.Content)
        $stream = [System.IO.MemoryStream]::new($bytes)
        $actualHash = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
        $stream.Dispose()
        
        if ($actualHash -ne $ExpectedHash) {
            Write-WinUtilLog -Level Error -Message "Hash mismatch! Expected: $ExpectedHash, Got: $actualHash" -Component "SecureDownload"
            throw "Integrity check failed: Hash mismatch. Possible MITM attack or corrupted download."
        }
        
        Write-WinUtilLog -Level Information -Message "Hash verification passed: $actualHash" -Component "SecureDownload"
        
        # Verify signature if requested
        if ($VerifySignature) {
            if (-not $OutputPath) {
                $OutputPath = [System.IO.Path]::GetTempFileName() + ".ps1"
            }
            
            Set-Content -Path $OutputPath -Value $content.Content -Encoding UTF8
            
            $signature = Get-AuthenticodeSignature -FilePath $OutputPath
            
            if ($signature.Status -ne 'Valid') {
                Remove-Item -Path $OutputPath -Force
                throw "Invalid signature: $($signature.Status). SignerCertificate: $($signature.SignerCertificate.Subject)"
            }
            
            Write-WinUtilLog -Level Information -Message "Signature verification passed. Signer: $($signature.SignerCertificate.Subject)" -Component "SecureDownload"
        }
        
        # Save to file if path specified
        if ($OutputPath -and -not $VerifySignature) {
            Set-Content -Path $OutputPath -Value $content.Content -Encoding UTF8
            Write-WinUtilLog -Level Information -Message "Content saved to: $OutputPath" -Component "SecureDownload"
        }
        
        return $content.Content
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Secure download failed: $_" -Component "SecureDownload"
        throw
    }
}
```

### Update Install-WinUtilChoco.ps1

**File:** `functions/private/Install-WinUtilChoco.ps1`

```powershell
function Install-WinUtilChoco {
    <#
    .SYNOPSIS
        Installs Chocolatey package manager with security verification
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Hash for Chocolatey install script (UPDATE THIS REGULARLY)
        $chocoInstallUrl = "https://community.chocolatey.org/install.ps1"
        $expectedHash = "PUT_ACTUAL_HASH_HERE"  # Get from: curl -sL $url | sha256sum
        
        Write-WinUtilLog -Level Information -Message "Installing Chocolatey with security verification" -Component "Chocolatey"
        
        # Download and verify
        $chocoScript = Invoke-WinUtilSecureDownload -Url $chocoInstallUrl -ExpectedHash $expectedHash
        
        # Execute in constrained language mode if possible
        $scriptBlock = [ScriptBlock]::Create($chocoScript)
        & $scriptBlock
        
        Write-WinUtilLog -Level Information -Message "Chocolatey installed successfully" -Component "Chocolatey"
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Failed to install Chocolatey: $_" -Component "Chocolatey"
        throw
    }
}
```

---

## 2. Replace Invoke-Expression

### Problem
Current code uses `Invoke-Expression` with config-based scripts:
```powershell
Invoke-Expression $script  # DANGEROUS
```

### Solution: Use whitelisted command registry

**File:** `functions/private/Invoke-WinUtilSafeScript.ps1`

```powershell
function Invoke-WinUtilSafeScript {
    <#
    .SYNOPSIS
        Executes pre-approved scripts safely without Invoke-Expression
    
    .DESCRIPTION
        Maintains a whitelist of approved script actions and executes them
        using script blocks instead of dynamic expression evaluation.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionName,
        
        [Parameter()]
        [hashtable]$Parameters = @{}
    )
    
    # Registry of approved script blocks
    $approvedActions = @{
        # Disk and File System
        'DiskCleanup' = {
            param($Drive = 'C:')
            Write-WinUtilLog -Level Information -Message "Running disk cleanup on $Drive" -Component "DiskCleanup"
            cleanmgr.exe /d $Drive /VERYLOWDISK
        }
        
        'DisableHibernation' = {
            Write-WinUtilLog -Level Information -Message "Disabling hibernation" -Component "Power"
            powercfg.exe /hibernate off
        }
        
        # Telemetry
        'DisableTelemetry' = {
            Write-WinUtilLog -Level Information -Message "Disabling telemetry services" -Component "Privacy"
            
            $services = @('DiagTrack', 'dmwappushservice')
            foreach ($service in $services) {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Registry tweaks
        'DisableActivityHistory' = {
            Write-WinUtilLog -Level Information -Message "Disabling activity history" -Component "Privacy"
            Set-WinUtilRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" `
                -Name "EnableActivityFeed" -Type "DWord" -Value 0
        }
        
        # Network
        'FlushDNS' = {
            Write-WinUtilLog -Level Information -Message "Flushing DNS cache" -Component "Network"
            ipconfig /flushdns
        }
        
        # Windows Update
        'ResetWindowsUpdate' = {
            Write-WinUtilLog -Level Information -Message "Resetting Windows Update components" -Component "WindowsUpdate"
            
            Stop-Service -Name wuauserv, cryptSvc, bits, msiserver -Force
            
            Remove-Item -Path "$env:SystemRoot\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:SystemRoot\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
            
            Start-Service -Name wuauserv, cryptSvc, bits, msiserver
        }
    }
    
    # Validate action exists in whitelist
    if (-not $approvedActions.ContainsKey($ActionName)) {
        $availableActions = $approvedActions.Keys -join ', '
        Write-WinUtilLog -Level Error -Message "Unauthorized script action: $ActionName. Available: $availableActions" -Component "Security"
        throw "Action '$ActionName' is not in the approved whitelist"
    }
    
    # Execute approved action
    try {
        Write-WinUtilLog -Level Information -Message "Executing approved action: $ActionName" -Component "ScriptExecution"
        
        $scriptBlock = $approvedActions[$ActionName]
        
        if ($Parameters.Count -gt 0) {
            & $scriptBlock @Parameters
        }
        else {
            & $scriptBlock
        }
        
        Write-WinUtilLog -Level Information -Message "Action completed successfully: $ActionName" -Component "ScriptExecution"
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Action failed: $ActionName - $_" -Component "ScriptExecution"
        throw
    }
}
```

### Update Invoke-WPFButton.ps1

**File:** `functions/public/Invoke-WPFButton.ps1`

```powershell
# OLD CODE (REMOVE):
# if ($buttonConfig.InvokeScript -and $buttonConfig.InvokeScript.Count -gt 0) {
#     foreach ($script in $buttonConfig.InvokeScript) {
#         if (-not [string]::IsNullOrWhiteSpace($script)) {
#             Invoke-Expression $script  # DANGEROUS
#         }
#     }
# }

# NEW CODE (ADD):
if ($buttonConfig.ActionName) {
    try {
        $params = if ($buttonConfig.Parameters) { $buttonConfig.Parameters } else { @{} }
        Invoke-WinUtilSafeScript -ActionName $buttonConfig.ActionName -Parameters $params
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to execute action: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}
```

### Update config/tweaks.json

**OLD FORMAT:**
```json
{
  "WPFTweakDiskCleanup": {
    "InvokeScript": [
      "cleanmgr.exe /d C: /VERYLOWDISK"
    ]
  }
}
```

**NEW FORMAT:**
```json
{
  "WPFTweakDiskCleanup": {
    "ActionName": "DiskCleanup",
    "Parameters": {
      "Drive": "C:"
    }
  }
}
```

---

## 3. Registry Validation

### Problem
No validation of registry paths allows arbitrary system modifications

### Solution: Implement strict registry validation

**File:** `functions/private/Set-WinUtilRegistry.ps1` (UPDATE)

```powershell
function Set-WinUtilRegistry {
    <#
    .SYNOPSIS
        Safely sets registry values with validation and logging
    
    .DESCRIPTION
        Validates registry paths against whitelist, creates backups,
        and logs all changes for audit purposes.
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9_\s-]+$')]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$Type,
        
        [Parameter(Mandatory)]
        [object]$Value,
        
        [Parameter()]
        [switch]$Force,
        
        [Parameter()]
        [switch]$CreateBackup = $true
    )
    
    # Whitelist of allowed registry path patterns
    $allowedPathPatterns = @(
        'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\.*',
        'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\.*',
        'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\.*',
        'HKCU:\\Control Panel\\.*',
        'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+\\Start$',  # Service startup type only
        'HKLM:\\SOFTWARE\\WinUtil\\.*'  # Our own registry key
    )
    
    # Blacklist of explicitly forbidden paths
    $forbiddenPathPatterns = @(
        'HKLM:\\SAM\\.*',
        'HKLM:\\SECURITY\\.*',
        'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\.*',  # Authentication
        '.*\\Run$',  # Startup persistence
        '.*\\RunOnce$',
        '.*\\Debugger$'  # Image file execution options
    )
    
    try {
        # Normalize path
        $Path = $Path.TrimEnd('\')
        
        # Check against blacklist first
        foreach ($forbidden in $forbiddenPathPatterns) {
            if ($Path -match $forbidden) {
                Write-WinUtilLog -Level Error -Message "Registry path is blacklisted: $Path" -Component "Registry"
                throw "Access denied: Registry path '$Path' is blacklisted for security reasons"
            }
        }
        
        # Check against whitelist
        $isAllowed = $false
        foreach ($pattern in $allowedPathPatterns) {
            if ($Path -match $pattern) {
                $isAllowed = $true
                break
            }
        }
        
        if (-not $isAllowed) {
            Write-WinUtilLog -Level Error -Message "Registry path not in whitelist: $Path" -Component "Registry"
            throw "Access denied: Registry path '$Path' is not in the approved whitelist"
        }
        
        # Create backup if requested
        if ($CreateBackup) {
            try {
                $backupPath = "C:\ProgramData\WinUtil\backups\registry"
                if (-not (Test-Path $backupPath)) {
                    New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
                }
                
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $backupFile = Join-Path $backupPath "backup_$timestamp.reg"
                
                # Export current value if it exists
                if (Test-Path $Path) {
                    $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
                    if ($currentValue) {
                        $backupData = @{
                            Path = $Path
                            Name = $Name
                            OldValue = $currentValue.$Name
                            OldType = (Get-Item $Path).GetValueKind($Name)
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                        $backupData | ConvertTo-Json | Out-File $backupFile
                        Write-WinUtilLog -Level Information -Message "Backup created: $backupFile" -Component "Registry"
                    }
                }
            }
            catch {
                Write-WinUtilLog -Level Warning -Message "Failed to create backup: $_" -Component "Registry"
            }
        }
        
        # Ensure path exists
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-WinUtilLog -Level Information -Message "Created registry path: $Path" -Component "Registry"
        }
        
        # Set the value
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set registry value to '$Value'")) {
            Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force:$Force
            
            Write-WinUtilLog -Level Information -Message "Registry modified: $Path\$Name = $Value (Type: $Type)" -Component "Registry"
        }
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Failed to set registry value: $_" -Component "Registry"
        throw
    }
}
```

---

## 4. Audit Logging System

### Problem
No logging of security-critical operations

### Solution: Comprehensive logging system

**File:** `functions/private/Write-WinUtilLog.ps1`

```powershell
function Write-WinUtilLog {
    <#
    .SYNOPSIS
        Writes audit logs for WinUtil operations
    
    .DESCRIPTION
        Writes structured logs to both file and Windows Event Log
        for audit and security monitoring purposes.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error', 'Security')]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter()]
        [string]$Component = 'General',
        
        [Parameter()]
        [hashtable]$AdditionalData = @{}
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $processId = $PID
        
        # Construct structured log entry
        $logEntry = @{
            Timestamp = $timestamp
            Level = $Level
            Component = $Component
            Message = $Message
            User = $username
            ProcessId = $processId
            MachineName = $env:COMPUTERNAME
        }
        
        # Add additional data if provided
        if ($AdditionalData.Count -gt 0) {
            $logEntry.AdditionalData = $AdditionalData
        }
        
        # Format for file logging
        $logLine = "[$timestamp] [$Level] [$Component] [$username] $Message"
        
        # Add additional data to log line
        if ($AdditionalData.Count -gt 0) {
            $additionalJson = $AdditionalData | ConvertTo-Json -Compress
            $logLine += " | Data: $additionalJson"
        }
        
        # Log to file
        $logDir = "C:\ProgramData\WinUtil\logs"
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        $logFile = Join-Path $logDir "winutil_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logLine -ErrorAction SilentlyContinue
        
        # Log to Windows Event Log (requires source registration)
        try {
            # Create event source if it doesn't exist
            if (-not [System.Diagnostics.EventLog]::SourceExists("WinUtil")) {
                New-EventLog -LogName Application -Source "WinUtil"
            }
            
            $eventType = switch ($Level) {
                'Information' { 'Information' }
                'Warning' { 'Warning' }
                'Error' { 'Error' }
                'Security' { 'Warning' }  # Security events as warnings for visibility
            }
            
            $eventId = switch ($Level) {
                'Information' { 1000 }
                'Warning' { 2000 }
                'Error' { 3000 }
                'Security' { 4000 }
            }
            
            $eventMessage = "Component: $Component`nUser: $username`nMessage: $Message"
            if ($AdditionalData.Count -gt 0) {
                $eventMessage += "`nAdditional Data: $($AdditionalData | ConvertTo-Json)"
            }
            
            Write-EventLog -LogName Application -Source "WinUtil" `
                -EventId $eventId -EntryType $eventType -Message $eventMessage `
                -ErrorAction SilentlyContinue
        }
        catch {
            # Fail silently if event log is not available
        }
        
        # Console output for development
        if ($env:WINUTIL_DEBUG -eq '1') {
            $color = switch ($Level) {
                'Information' { 'Green' }
                'Warning' { 'Yellow' }
                'Error' { 'Red' }
                'Security' { 'Cyan' }
            }
            Write-Host $logLine -ForegroundColor $color
        }
    }
    catch {
        # Last resort: write to console
        Write-Warning "Logging failed: $_"
    }
}
```

### Initialize logging on startup

**File:** `scripts/start.ps1` (ADD AT TOP)

```powershell
# Initialize logging system
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("WinUtil")) {
        New-EventLog -LogName Application -Source "WinUtil" -ErrorAction SilentlyContinue
    }
}
catch {
    # Continue if event log creation fails (non-admin scenarios)
}

Write-WinUtilLog -Level Information -Message "WinUtil started" -Component "Startup" -AdditionalData @{
    Version = $sync.version
    User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
```

---

## 5. JSON Schema Validation

### Problem
No validation of configuration file structure

### Solution: JSON Schema validation

**File:** `config/schema.json` (CREATE NEW)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "WinUtil Configuration Schema",
  "type": "object",
  "properties": {
    "ActionName": {
      "type": "string",
      "pattern": "^[A-Za-z]+$",
      "description": "Name of the approved action to execute"
    },
    "Parameters": {
      "type": "object",
      "description": "Parameters to pass to the action"
    },
    "Content": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "Description": {
      "type": "string",
      "maxLength": 500
    },
    "Category": {
      "type": "string",
      "enum": ["Essential", "Optional", "Advanced"]
    },
    "Panel": {
      "type": "string"
    }
  },
  "required": ["ActionName"],
  "additionalProperties": true
}
```

**File:** `functions/private/Test-WinUtilConfigSchema.ps1` (CREATE NEW)

```powershell
function Test-WinUtilConfigSchema {
    <#
    .SYNOPSIS
        Validates configuration JSON against schema
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigJson,
        
        [Parameter(Mandatory)]
        [string]$SchemaPath
    )
    
    try {
        if (-not (Test-Path $SchemaPath)) {
            throw "Schema file not found: $SchemaPath"
        }
        
        $schema = Get-Content $SchemaPath -Raw
        
        # Use Test-Json cmdlet (PowerShell 6+) or custom validation
        if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
            $isValid = Test-Json -Json $ConfigJson -Schema $schema
            
            if (-not $isValid) {
                throw "JSON validation failed against schema"
            }
        }
        else {
            # Basic validation for PowerShell 5.1
            $config = $ConfigJson | ConvertFrom-Json
            
            # Validate required fields
            if (-not $config.ActionName) {
                throw "Required field 'ActionName' is missing"
            }
            
            # Validate ActionName pattern
            if ($config.ActionName -notmatch '^[A-Za-z]+$') {
                throw "ActionName must contain only letters"
            }
        }
        
        Write-WinUtilLog -Level Information -Message "Configuration validated successfully" -Component "ConfigValidation"
        return $true
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Configuration validation failed: $_" -Component "ConfigValidation"
        throw
    }
}
```

---

## 6. Digital Signature Verification

### Problem
No verification of script authenticity

### Solution: Authenticode signature verification

**File:** `functions/private/Test-WinUtilScriptSignature.ps1` (CREATE NEW)

```powershell
function Test-WinUtilScriptSignature {
    <#
    .SYNOPSIS
        Verifies the digital signature of a PowerShell script
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$FilePath,
        
        [Parameter()]
        [string[]]$TrustedPublishers = @(
            "CN=Chris Titus Tech",
            "CN=Microsoft Corporation"
        )
    )
    
    process {
        try {
            if (-not (Test-Path $FilePath)) {
                throw "File not found: $FilePath"
            }
            
            $signature = Get-AuthenticodeSignature -FilePath $FilePath
            
            # Check signature status
            if ($signature.Status -ne 'Valid') {
                Write-WinUtilLog -Level Error -Message "Invalid signature status: $($signature.Status) for file: $FilePath" -Component "SignatureVerification"
                return $false
            }
            
            # Check certificate
            $certSubject = $signature.SignerCertificate.Subject
            $isTrusted = $false
            
            foreach ($publisher in $TrustedPublishers) {
                if ($certSubject -like "*$publisher*") {
                    $isTrusted = $true
                    break
                }
            }
            
            if (-not $isTrusted) {
                Write-WinUtilLog -Level Warning -Message "Signer not in trusted list: $certSubject" -Component "SignatureVerification"
                return $false
            }
            
            # Check certificate validity
            $now = Get-Date
            if ($signature.SignerCertificate.NotAfter -lt $now) {
                Write-WinUtilLog -Level Error -Message "Certificate expired: $($signature.SignerCertificate.NotAfter)" -Component "SignatureVerification"
                return $false
            }
            
            if ($signature.SignerCertificate.NotBefore -gt $now) {
                Write-WinUtilLog -Level Error -Message "Certificate not yet valid: $($signature.SignerCertificate.NotBefore)" -Component "SignatureVerification"
                return $false
            }
            
            Write-WinUtilLog -Level Information -Message "Signature valid for: $FilePath, Signer: $certSubject" -Component "SignatureVerification"
            return $true
        }
        catch {
            Write-WinUtilLog -Level Error -Message "Signature verification failed: $_" -Component "SignatureVerification"
            return $false
        }
    }
}
```

### How to sign scripts

```powershell
# Get code signing certificate
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

# Sign script
Set-AuthenticodeSignature -FilePath "winutil.ps1" -Certificate $cert -TimestampServer "http://timestamp.digicert.com"

# Verify
Get-AuthenticodeSignature -FilePath "winutil.ps1"
```

---

## 7. Rollback Mechanism

### Problem
No way to undo changes

### Solution: Backup and restore functionality

**File:** `functions/private/Backup-WinUtilState.ps1` (CREATE NEW)

```powershell
function Backup-WinUtilState {
    <#
    .SYNOPSIS
        Creates a backup of system state before modifications
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$BackupName = "Auto_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    try {
        $backupPath = "C:\ProgramData\WinUtil\backups\$BackupName"
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        
        # Create system restore point
        try {
            Checkpoint-Computer -Description "WinUtil Backup: $BackupName" -RestorePointType MODIFY_SETTINGS
            Write-WinUtilLog -Level Information -Message "System restore point created: $BackupName" -Component "Backup"
        }
        catch {
            Write-WinUtilLog -Level Warning -Message "Failed to create restore point: $_" -Component "Backup"
        }
        
        # Export registry keys that will be modified
        $registryPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        )
        
        foreach ($path in $registryPaths) {
            if (Test-Path $path) {
                $safePath = $path -replace ':', '' -replace '\\', '_'
                $exportFile = Join-Path $backupPath "$safePath.reg"
                reg export $path.Replace(':', '') $exportFile /y 2>$null
            }
        }
        
        # Save backup metadata
        $metadata = @{
            BackupName = $BackupName
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            ComputerName = $env:COMPUTERNAME
        }
        
        $metadata | ConvertTo-Json | Out-File (Join-Path $backupPath "metadata.json")
        
        Write-WinUtilLog -Level Information -Message "Backup completed: $backupPath" -Component "Backup"
        return $backupPath
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Backup failed: $_" -Component "Backup"
        throw
    }
}

function Restore-WinUtilState {
    <#
    .SYNOPSIS
        Restores system state from backup
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BackupPath
    )
    
    try {
        if (-not (Test-Path $BackupPath)) {
            throw "Backup not found: $BackupPath"
        }
        
        Write-WinUtilLog -Level Information -Message "Starting restore from: $BackupPath" -Component "Restore"
        
        # Import registry files
        Get-ChildItem -Path $BackupPath -Filter "*.reg" | ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.FullName, "Import registry file")) {
                reg import $_.FullName 2>$null
                Write-WinUtilLog -Level Information -Message "Restored registry from: $($_.Name)" -Component "Restore"
            }
        }
        
        Write-WinUtilLog -Level Information -Message "Restore completed successfully" -Component "Restore"
    }
    catch {
        Write-WinUtilLog -Level Error -Message "Restore failed: $_" -Component "Restore"
        throw
    }
}
```

---

## 8. Rate Limiting

### Problem
No protection against abuse or rapid-fire attacks

### Solution: Rate limiting for network operations

**File:** `functions/private/Test-WinUtilRateLimit.ps1` (CREATE NEW)

```powershell
function Test-WinUtilRateLimit {
    <#
    .SYNOPSIS
        Implements rate limiting for operations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OperationName,
        
        [Parameter()]
        [int]$MaxRequestsPerMinute = 10,
        
        [Parameter()]
        [int]$MinIntervalSeconds = 5
    )
    
    # Initialize rate limit tracking
    if (-not $script:RateLimitTracker) {
        $script:RateLimitTracker = @{}
    }
    
    $now = Get-Date
    
    if (-not $script:RateLimitTracker.ContainsKey($OperationName)) {
        $script:RateLimitTracker[$OperationName] = @{
            Requests = @()
            LastRequest = $null
        }
    }
    
    $tracker = $script:RateLimitTracker[$OperationName]
    
    # Check minimum interval
    if ($tracker.LastRequest) {
        $elapsed = ($now - $tracker.LastRequest).TotalSeconds
        if ($elapsed -lt $MinIntervalSeconds) {
            $waitTime = [math]::Ceiling($MinIntervalSeconds - $elapsed)
            Write-WinUtilLog -Level Warning -Message "Rate limit: Must wait $waitTime seconds before $OperationName" -Component "RateLimit"
            throw "Rate limit exceeded. Please wait $waitTime seconds."
        }
    }
    
    # Clean old requests (older than 1 minute)
    $oneMinuteAgo = $now.AddMinutes(-1)
    $tracker.Requests = $tracker.Requests | Where-Object { $_ -gt $oneMinuteAgo }
    
    # Check requests per minute
    if ($tracker.Requests.Count -ge $MaxRequestsPerMinute) {
        Write-WinUtilLog -Level Warning -Message "Rate limit: Max $MaxRequestsPerMinute requests per minute exceeded for $OperationName" -Component "RateLimit"
        throw "Rate limit exceeded. Maximum $MaxRequestsPerMinute requests per minute allowed."
    }
    
    # Update tracker
    $tracker.Requests += $now
    $tracker.LastRequest = $now
    
    return $true
}
```

---

## Implementation Checklist

### Phase 1 - Critical (Week 1)
- [ ] Create `Write-WinUtilLog.ps1`
- [ ] Create `Invoke-WinUtilSecureDownload.ps1`
- [ ] Update `Install-WinUtilChoco.ps1`
- [ ] Create `Invoke-WinUtilSafeScript.ps1`
- [ ] Update `Invoke-WPFButton.ps1`
- [ ] Update `Set-WinUtilRegistry.ps1`
- [ ] Test all critical changes

### Phase 2 - High Priority (Week 2)
- [ ] Create JSON schema `schema.json`
- [ ] Create `Test-WinUtilConfigSchema.ps1`
- [ ] Create `Test-WinUtilScriptSignature.ps1`
- [ ] Update config files to new format
- [ ] Sign all scripts with certificate

### Phase 3 - Medium Priority (Week 3-4)
- [ ] Create `Backup-WinUtilState.ps1`
- [ ] Create `Restore-WinUtilState.ps1`
- [ ] Create `Test-WinUtilRateLimit.ps1`
- [ ] Add backup calls before modifications
- [ ] Integrate rate limiting

### Phase 4 - Testing & Documentation (Week 5)
- [ ] Unit tests for each function
- [ ] Integration tests
- [ ] Security audit
- [ ] Update user documentation
- [ ] Create security runbook

---

## Testing Commands

```powershell
# Test secure download
Invoke-WinUtilSecureDownload -Url "https://example.com/script.ps1" `
    -ExpectedHash "ABC123..." -VerifySignature

# Test safe script execution
Invoke-WinUtilSafeScript -ActionName "DiskCleanup" -Parameters @{ Drive = "C:" }

# Test registry validation
Set-WinUtilRegistry -Path "HKLM:\SOFTWARE\WinUtil\Test" `
    -Name "TestValue" -Type "String" -Value "Test" -WhatIf

# Test logging
Write-WinUtilLog -Level Information -Message "Test message" `
    -Component "Test" -AdditionalData @{ Key = "Value" }

# Test backup
$backup = Backup-WinUtilState -BackupName "TestBackup"
Restore-WinUtilState -BackupPath $backup -WhatIf

# Test rate limiting
Test-WinUtilRateLimit -OperationName "Download" `
    -MaxRequestsPerMinute 5 -MinIntervalSeconds 10
```

---

**Document Version:** 1.0  
**Last Updated:** 2026-02-25  
**Status:** Draft - Awaiting Implementation
