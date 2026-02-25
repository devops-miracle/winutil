function Write-WinUtilLog {
    <#
    .SYNOPSIS
        Writes audit logs for WinUtil operations
    
    .DESCRIPTION
        Writes structured logs to both file and Windows Event Log
        for audit and security monitoring purposes.
    
    .PARAMETER Level
        The severity level of the log entry (Information, Warning, Error, Security)
    
    .PARAMETER Message
        The message to log
    
    .PARAMETER Component
        The component or module generating the log entry
    
    .PARAMETER AdditionalData
        Optional hashtable of additional data to include in the log
    
    .EXAMPLE
        Write-WinUtilLog -Level Information -Message "Operation completed" -Component "Registry"
    
    .EXAMPLE
        Write-WinUtilLog -Level Error -Message "Failed to install package" -Component "Chocolatey" -AdditionalData @{Package="vim"}
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
        
        # Format for file logging
        $logLine = "[$timestamp] [$Level] [$Component] [$username] $Message"
        
        # Add additional data to log line if provided
        if ($AdditionalData.Count -gt 0) {
            $additionalJson = $AdditionalData | ConvertTo-Json -Compress
            $logLine += " | Data: $additionalJson"
        }
        
        # Log to file
        $logDir = "$env:ProgramData\WinUtil\logs"
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        
        $logFile = Join-Path $logDir "winutil_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $logFile -Value $logLine -ErrorAction SilentlyContinue
        
        # Log to Windows Event Log (requires source registration)
        try {
            # Create event source if it doesn't exist (requires admin)
            if (-not [System.Diagnostics.EventLog]::SourceExists("WinUtil")) {
                # Try to create source, but don't fail if we can't
                try {
                    New-EventLog -LogName Application -Source "WinUtil" -ErrorAction SilentlyContinue
                } catch {
                    # Silently continue if we can't create event source
                }
            }
            
            if ([System.Diagnostics.EventLog]::SourceExists("WinUtil")) {
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
        }
        catch {
            # Fail silently if event log is not available
        }
        
        # Console output for immediate feedback
        $color = switch ($Level) {
            'Information' { 'Green' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
            'Security' { 'Cyan' }
            default { 'White' }
        }
        
        # Only write to console in verbose mode or for errors
        if ($Level -eq 'Error' -or $VerbosePreference -eq 'Continue') {
            Write-Host $logLine -ForegroundColor $color
        }
    }
    catch {
        # Last resort: write to console if logging fails
        Write-Warning "Logging failed: $_"
    }
}
