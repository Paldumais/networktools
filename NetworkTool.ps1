<#
.SYNOPSIS
    Professional Network Analysis and Reset Tool
.DESCRIPTION
    Enterprise-grade network troubleshooting tool with comprehensive diagnostics,
    security validation, and robust error handling.
.AUTHOR
    Network Tool v2.0
.VERSION
    2.0.0
.PARAMETER LogPath
    Custom path for log files (default: Documents\NetworkTool)
.PARAMETER Mode
    Operation mode: Info, Diagnostic, Reset, SpeedTest, Full
.PARAMETER Silent
    Run without user interaction
.PARAMETER NoRestart
    Skip restart prompts
.PARAMETER ConfigFile
    Path to configuration file
.EXAMPLE
    .\NetworkTool.ps1 -Mode Info
    .\NetworkTool.ps1 -Mode Full -Silent
    .\NetworkTool.ps1 -Mode Reset -LogPath "C:\Logs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$LogPath = "$env:USERPROFILE\Documents\NetworkTool",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Info", "Diagnostic", "Reset", "SpeedTest", "Full", "Menu")]
    [string]$Mode = "Menu",
    
    [Parameter(Mandatory=$false)]
    [switch]$Silent,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoRestart,
    
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigFile
)

#Requires -Version 3.0

# Security and stability settings
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$VerbosePreference = if ($PSBoundParameters.ContainsKey('Verbose')) { "Continue" } else { "SilentlyContinue" }

# Global configuration
$Global:Config = @{
    Version = "2.0.0"
    MaxLogSize = 10MB
    MaxLogFiles = 5
    TimeoutSeconds = 30
    RetryAttempts = 3
    SpeedTestUrls = @(
        "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
        "http://speedtest.ftp.otenet.gr/files/test10Mb.db"
    )
    PingTargets = @("8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9")
    RequiredServices = @("Dhcp", "Dnscache", "Winmgmt", "Netman", "NlaSvc")
}

# Initialize secure logging
function Initialize-Logging {
    param([string]$LogDirectory)
    
    try {
        # Create log directory with proper permissions
        if (-not (Test-Path $LogDirectory)) {
            $null = New-Item -Path $LogDirectory -ItemType Directory -Force
            
            # Set secure permissions (owner full control only)
            $acl = Get-Acl $LogDirectory
            $acl.SetAccessRuleProtection($true, $false)
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $LogDirectory -AclObject $acl
        }
        
        # Clean old logs
        Get-ChildItem -Path $LogDirectory -Filter "NetworkTool_*.log" | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -Skip $Global:Config.MaxLogFiles | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        
        # Create new log file
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $logFile = Join-Path $LogDirectory "NetworkTool_$timestamp.log"
        
        # Initialize log with header
        $header = @"
================================================================================
Network Analysis and Reset Tool v$($Global:Config.Version)
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Computer: $env:COMPUTERNAME
PowerShell: $($PSVersionTable.PSVersion)
OS: $((Get-CimInstance Win32_OperatingSystem).Caption)
================================================================================

"@
        $header | Out-File -FilePath $logFile -Encoding UTF8
        return $logFile
        
    } catch {
        # Fallback to temp directory
        $tempLog = Join-Path $env:TEMP "NetworkTool_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
        "Network Tool Log - Fallback location" | Out-File -FilePath $tempLog -Encoding UTF8
        return $tempLog
    }
}

# Secure logging function
function Write-SecureLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "DEBUG", "HEADER")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoConsole
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $logEntry = "[$timestamp] [$Level] $Message"
        
        # Console output with colors
        if (-not $NoConsole -and -not $Silent) {
            $color = switch ($Level) {
                "ERROR"   { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "INFO"    { "Cyan" }
                "DEBUG"   { "Gray" }
                "HEADER"  { "Magenta" }
                default   { "White" }
            }
            Write-Host $logEntry -ForegroundColor $color
        }
        
        # File output with size management
        if ($Global:LogFile) {
            Add-Content -Path $Global:LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
            
            # Rotate log if too large
            if ((Get-Item $Global:LogFile -ErrorAction SilentlyContinue).Length -gt $Global:Config.MaxLogSize) {
                $rotatedLog = $Global:LogFile -replace '\.log$', "_rotated_$(Get-Date -Format 'HHmmss').log"
                Move-Item $Global:LogFile $rotatedLog -ErrorAction SilentlyContinue
                "Log rotated to: $rotatedLog" | Out-File -FilePath $Global:LogFile -Encoding UTF8
            }
        }
        
    } catch {
        if (-not $NoConsole) {
            Write-Host "Logging error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Security validation functions
function Test-ExecutionSecurity {
    Write-SecureLog "Performing security validation..." "INFO"
    
    $securityIssues = @()
    
    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    if ($executionPolicy -eq "Restricted") {
        $securityIssues += "Execution policy is Restricted"
    }
    Write-SecureLog "Execution Policy: $executionPolicy" "INFO"
    
    # Check if running from network location
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath -and $scriptPath.StartsWith("\\")) {
        $securityIssues += "Script is running from network location"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 3) {
        $securityIssues += "PowerShell version is outdated (minimum 3.0 required)"
    }
    Write-SecureLog "PowerShell Version: $($PSVersionTable.PSVersion)" "INFO"
    
    # Check user context
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal] $currentUser).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-SecureLog "Administrator Rights: $isAdmin" "INFO"
    Write-SecureLog "Current User: $($currentUser.Name)" "INFO"
    
    if ($securityIssues.Count -gt 0) {
        Write-SecureLog "Security issues detected:" "WARNING"
        foreach ($issue in $securityIssues) {
            Write-SecureLog "  - $issue" "WARNING"
        }
    } else {
        Write-SecureLog "Security validation passed" "SUCCESS"
    }
    
    return @{
        IsAdmin = $isAdmin
        Issues = $securityIssues
        Safe = $securityIssues.Count -eq 0
    }
}

# Robust network information gathering
function Get-NetworkInformation {
    Write-SecureLog "`n=== NETWORK INFORMATION ANALYSIS ===" "HEADER"
    
    $networkInfo = @{
        Adapters = @()
        Connectivity = @{}
        DNS = @{}
        Routes = @()
        Services = @{}
        Statistics = @{}
    }
    
    try {
        # Get network adapters with retry logic
        $adapters = Invoke-WithRetry -ScriptBlock {
            if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
                Get-NetAdapter | Sort-Object Name
            } else {
                Get-WmiObject Win32_NetworkAdapter | Where-Object {$_.NetConnectionStatus -ne $null}
            }
        } -MaxRetries $Global:Config.RetryAttempts
        
        Write-SecureLog "Found $($adapters.Count) network adapters" "INFO"
        
        foreach ($adapter in $adapters) {
            $adapterInfo = @{
                Name = $adapter.Name
                Status = $adapter.Status
                MAC = $adapter.MacAddress
                Speed = $adapter.LinkSpeed
                Type = $adapter.InterfaceDescription
                IPv4 = @()
                IPv6 = @()
                Gateway = $null
                DNS = @()
            }
            
            try {
                if ($adapter.Status -eq "Up" -or $adapter.NetConnectionStatus -eq 2) {
                    # Get IP configuration
                    if (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
                        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                        if ($ipConfig) {
                            $adapterInfo.IPv4 = $ipConfig.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }
                            $adapterInfo.IPv6 = $ipConfig.IPv6Address | Where-Object {$_.AddressState -eq "Preferred"} | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }
                            $adapterInfo.Gateway = $ipConfig.IPv4DefaultGateway.NextHop
                        }
                    } else {
                        # Fallback to WMI
                        $wmiConfig = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.Index -eq $adapter.Index}
                        if ($wmiConfig -and $wmiConfig.IPAddress) {
                            $adapterInfo.IPv4 = $wmiConfig.IPAddress | Where-Object {$_ -match '^\d+\.\d+\.\d+\.\d+$'}
                            $adapterInfo.Gateway = $wmiConfig.DefaultIPGateway | Select-Object -First 1
                            $adapterInfo.DNS = $wmiConfig.DNSServerSearchOrder
                        }
                    }
                }
            } catch {
                Write-SecureLog "Error getting configuration for adapter $($adapter.Name): $($_.Exception.Message)" "WARNING"
            }
            
            $networkInfo.Adapters += $adapterInfo
            
            # Display adapter information
            $statusIcon = if ($adapter.Status -eq "Up" -or $adapter.NetConnectionStatus -eq 2) { "🟢" } else { "🔴" }
            Write-SecureLog "$statusIcon $($adapterInfo.Name)" "INFO"
            Write-SecureLog "  Type: $($adapterInfo.Type)" "INFO"
            Write-SecureLog "  MAC: $($adapterInfo.MAC)" "INFO"
            if ($adapterInfo.Speed) { Write-SecureLog "  Speed: $($adapterInfo.Speed)" "INFO" }
            if ($adapterInfo.IPv4) { Write-SecureLog "  IPv4: $($adapterInfo.IPv4 -join ', ')" "INFO" }
            if ($adapterInfo.Gateway) { Write-SecureLog "  Gateway: $($adapterInfo.Gateway)" "INFO" }
            if ($adapterInfo.DNS) { Write-SecureLog "  DNS: $($adapterInfo.DNS -join ', ')" "INFO" }
        }
        
    } catch {
        Write-SecureLog "Error gathering network adapter information: $($_.Exception.Message)" "ERROR"
    }
    
    # Test connectivity
    Write-SecureLog "`n--- CONNECTIVITY ANALYSIS ---" "HEADER"
    foreach ($target in $Global:Config.PingTargets) {
        try {
            $connectivity = Test-Connection -ComputerName $target -Count 2 -Quiet -ErrorAction Stop
            $networkInfo.Connectivity[$target] = $connectivity
            $status = if ($connectivity) { "SUCCESS" } else { "ERROR" }
            Write-SecureLog "Connectivity to $target`: $connectivity" $status
        } catch {
            $networkInfo.Connectivity[$target] = $false
            Write-SecureLog "Connectivity to $target`: Failed ($($_.Exception.Message))" "ERROR"
        }
    }
    
    # DNS Resolution Test
    Write-SecureLog "`n--- DNS RESOLUTION TEST ---" "HEADER"
    $dnsTargets = @("google.com", "microsoft.com", "github.com")
    foreach ($target in $dnsTargets) {
        try {
            $resolved = Resolve-DnsName $target -ErrorAction Stop
            $networkInfo.DNS[$target] = $true
            Write-SecureLog "DNS resolution for $target`: SUCCESS" "SUCCESS"
        } catch {
            $networkInfo.DNS[$target] = $false
            Write-SecureLog "DNS resolution for $target`: FAILED" "ERROR"
        }
    }
    
    return $networkInfo
}

# Network speed testing with multiple methods
function Test-NetworkSpeed {
    Write-SecureLog "`n=== NETWORK SPEED ANALYSIS ===" "HEADER"
    
    $speedResults = @{
        Download = @()
        Latency = @{}
        Timestamp = Get-Date
    }
    
    # Download speed test
    Write-SecureLog "Testing download speed..." "INFO"
    foreach ($url in $Global:Config.SpeedTestUrls) {
        try {
            $fileName = Split-Path $url -Leaf
            Write-SecureLog "Testing with $fileName..." "INFO"
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "NetworkTool/$($Global:Config.Version)")
            
            # Set timeout
            $webClient.Timeout = $Global:Config.TimeoutSeconds * 1000
            
            $data = $webClient.DownloadData($url)
            $stopwatch.Stop()
            
            $fileSizeMB = $data.Length / 1MB
            $timeSec = $stopwatch.Elapsed.TotalSeconds
            $speedMbps = ($fileSizeMB * 8) / $timeSec
            
            $result = @{
                FileName = $fileName
                SizeMB = [math]::Round($fileSizeMB, 2)
                TimeSeconds = [math]::Round($timeSec, 2)
                SpeedMbps = [math]::Round($speedMbps, 2)
                Success = $true
            }
            
            $speedResults.Download += $result
            Write-SecureLog "  $fileName`: $([math]::Round($speedMbps, 2)) Mbps ($([math]::Round($fileSizeMB, 2)) MB in $([math]::Round($timeSec, 2))s)" "SUCCESS"
            
            $webClient.Dispose()
            
        } catch {
            Write-SecureLog "  Speed test failed for $fileName`: $($_.Exception.Message)" "WARNING"
            $speedResults.Download += @{
                FileName = $fileName
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Calculate average speed
    $successfulTests = $speedResults.Download | Where-Object {$_.Success}
    if ($successfulTests.Count -gt 0) {
        $avgSpeed = ($successfulTests | Measure-Object SpeedMbps -Average).Average
        Write-SecureLog "Average Download Speed: $([math]::Round($avgSpeed, 2)) Mbps" "SUCCESS"
        $speedResults.AverageSpeedMbps = [math]::Round($avgSpeed, 2)
    }
    
    # Latency testing
    Write-SecureLog "`n--- LATENCY ANALYSIS ---" "HEADER"
    foreach ($target in $Global:Config.PingTargets) {
        try {
            $pingResults = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop
            $avgLatency = ($pingResults | Measure-Object ResponseTime -Average).Average
            $minLatency = ($pingResults | Measure-Object ResponseTime -Minimum).Minimum
            $maxLatency = ($pingResults | Measure-Object ResponseTime -Maximum).Maximum
            
            $speedResults.Latency[$target] = @{
                Average = [math]::Round($avgLatency, 0)
                Minimum = $minLatency
                Maximum = $maxLatency
                PacketLoss = 0
            }
            
            Write-SecureLog "Latency to $target`: Avg=$([math]::Round($avgLatency, 0))ms, Min=$($minLatency)ms, Max=$($maxLatency)ms" "INFO"
            
        } catch {
            Write-SecureLog "Latency test to $target failed: $($_.Exception.Message)" "WARNING"
            $speedResults.Latency[$target] = @{
                Error = $_.Exception.Message
                PacketLoss = 100
            }
        }
    }
    
    return $speedResults
}

# Comprehensive network diagnostics
function Start-NetworkDiagnostics {
    Write-SecureLog "`n=== COMPREHENSIVE NETWORK DIAGNOSTICS ===" "HEADER"
    
    $diagnostics = @{
        Timestamp = Get-Date
        SystemInfo = @{}
        NetworkStack = @{}
        Services = @{}
        Firewall = @{}
        Performance = @{}
        Issues = @()
        Recommendations = @()
    }
    
    # System information
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $computer = Get-CimInstance Win32_ComputerSystem
        
        $diagnostics.SystemInfo = @{
            OS = $os.Caption
            Version = $os.Version
            Architecture = $os.OSArchitecture
            TotalMemoryGB = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
            Uptime = (Get-Date) - $os.LastBootUpTime
        }
        
        Write-SecureLog "System: $($diagnostics.SystemInfo.OS) $($diagnostics.SystemInfo.Architecture)" "INFO"
        Write-SecureLog "Uptime: $($diagnostics.SystemInfo.Uptime.Days) days, $($diagnostics.SystemInfo.Uptime.Hours) hours" "INFO"
        
    } catch {
        Write-SecureLog "Error gathering system information: $($_.Exception.Message)" "WARNING"
    }
    
    # Network services status
    Write-SecureLog "`n--- NETWORK SERVICES STATUS ---" "HEADER"
    foreach ($serviceName in $Global:Config.RequiredServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            $diagnostics.Services[$serviceName] = @{
                Status = $service.Status
                StartType = $service.StartType
                DisplayName = $service.DisplayName
            }
            
            $status = if ($service.Status -eq "Running") { "SUCCESS" } else { "WARNING" }
            Write-SecureLog "$($service.DisplayName): $($service.Status)" $status
            
            if ($service.Status -ne "Running") {
                $diagnostics.Issues += "Service '$($service.DisplayName)' is not running"
                $diagnostics.Recommendations += "Consider starting the '$($service.DisplayName)' service"
            }
            
        } catch {
            Write-SecureLog "Service $serviceName`: Not found or inaccessible" "ERROR"
            $diagnostics.Issues += "Service '$serviceName' is not available"
        }
    }
    
    # Windows Firewall status
    Write-SecureLog "`n--- FIREWALL STATUS ---" "HEADER"
    try {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            $firewallProfiles = Get-NetFirewallProfile
            foreach ($profile in $firewallProfiles) {
                $diagnostics.Firewall[$profile.Name] = @{
                    Enabled = $profile.Enabled
                    DefaultInboundAction = $profile.DefaultInboundAction
                    DefaultOutboundAction = $profile.DefaultOutboundAction
                }
                Write-SecureLog "$($profile.Name) Profile: Enabled=$($profile.Enabled), Inbound=$($profile.DefaultInboundAction), Outbound=$($profile.DefaultOutboundAction)" "INFO"
            }
        } else {
            # Fallback for older systems
            $firewall = netsh advfirewall show allprofiles state
            Write-SecureLog "Firewall status (legacy): $($firewall -join ' ')" "INFO"
        }
    } catch {
        Write-SecureLog "Error checking firewall status: $($_.Exception.Message)" "WARNING"
    }
    
    # Network performance counters
    Write-SecureLog "`n--- NETWORK PERFORMANCE ---" "HEADER"
    try {
        if (Get-Command Get-NetAdapterStatistics -ErrorAction SilentlyContinue) {
            $stats = Get-NetAdapterStatistics | Where-Object {$_.Name -in (Get-NetAdapter | Where-Object Status -eq "Up").Name}
            foreach ($stat in $stats) {
                $diagnostics.Performance[$stat.Name] = @{
                    BytesSentMB = [math]::Round($stat.BytesSent / 1MB, 2)
                    BytesReceivedMB = [math]::Round($stat.BytesReceived / 1MB, 2)
                    PacketsSent = $stat.PacketsSent
                    PacketsReceived = $stat.PacketsReceived
                    PacketsOutboundErrors = $stat.PacketsOutboundErrors
                    PacketsReceivedErrors = $stat.PacketsReceivedErrors
                }
                
                Write-SecureLog "$($stat.Name) Statistics:" "INFO"
                Write-SecureLog "  Data Sent: $([math]::Round($stat.BytesSent / 1MB, 2)) MB" "INFO"
                Write-SecureLog "  Data Received: $([math]::Round($stat.BytesReceived / 1MB, 2)) MB" "INFO"
                Write-SecureLog "  Packets Sent: $($stat.PacketsSent)" "INFO"
                Write-SecureLog "  Packets Received: $($stat.PacketsReceived)" "INFO"
                
                if ($stat.PacketsOutboundErrors -gt 0 -or $stat.PacketsReceivedErrors -gt 0) {
                    Write-SecureLog "  Errors: Out=$($stat.PacketsOutboundErrors), In=$($stat.PacketsReceivedErrors)" "WARNING"
                    $diagnostics.Issues += "Network errors detected on adapter '$($stat.Name)'"
                }
            }
        }
    } catch {
        Write-SecureLog "Error gathering network statistics: $($_.Exception.Message)" "WARNING"
    }
    
    # Generate recommendations
    if ($diagnostics.Issues.Count -eq 0) {
        Write-SecureLog "`nDiagnostics completed: No issues detected" "SUCCESS"
    } else {
        Write-SecureLog "`nDiagnostics completed: $($diagnostics.Issues.Count) issues found" "WARNING"
        Write-SecureLog "Issues detected:" "WARNING"
        foreach ($issue in $diagnostics.Issues) {
            Write-SecureLog "  - $issue" "WARNING"
        }
        
        if ($diagnostics.Recommendations.Count -gt 0) {
            Write-SecureLog "Recommendations:" "INFO"
            foreach ($recommendation in $diagnostics.Recommendations) {
                Write-SecureLog "  - $recommendation" "INFO"
            }
        }
    }
    
    return $diagnostics
}

# Secure network reset operations
function Start-NetworkReset {
    param([switch]$Force)
    
    Write-SecureLog "`n=== NETWORK RESET OPERATIONS ===" "HEADER"
    
    # Verify admin rights
    $security = Test-ExecutionSecurity
    if (-not $security.IsAdmin) {
        Write-SecureLog "Administrator privileges required for network reset operations" "ERROR"
        return $false
    }
    
    if (-not $Force -and -not $Silent) {
        Write-Host "`nWARNING: This will reset your network configuration!" -ForegroundColor Red
        Write-Host "The following operations will be performed:" -ForegroundColor Yellow
        Write-Host "• Flush DNS cache" -ForegroundColor White
        Write-Host "• Release and renew IP configuration" -ForegroundColor White
        Write-Host "• Reset Winsock catalog" -ForegroundColor White
        Write-Host "• Reset TCP/IP stack" -ForegroundColor White
        Write-Host "• Clear ARP and NetBIOS caches" -ForegroundColor White
        Write-Host "• Restart network services" -ForegroundColor White
        
        $confirm = Read-Host "`nDo you want to continue? (yes/no)"
        if ($confirm -ne "yes") {
            Write-SecureLog "Network reset cancelled by user" "INFO"
            return $false
        }
    }
    
    $resetOperations = @(
        @{Name="DNS Cache Flush"; Command="ipconfig /flushdns"; Critical=$false; RequiresRestart=$false},
        @{Name="IP Configuration Release"; Command="ipconfig /release"; Critical=$false; RequiresRestart=$false},
        @{Name="IP Configuration Renew"; Command="ipconfig /renew"; Critical=$false; RequiresRestart=$false},
        @{Name="ARP Cache Clear"; Command="arp -d *"; Critical=$false; RequiresRestart=$false},
        @{Name="NetBIOS Cache Reset"; Command="nbtstat -R"; Critical=$false; RequiresRestart=$false},
        @{Name="NetBIOS Names Refresh"; Command="nbtstat -RR"; Critical=$false; RequiresRestart=$false},
        @{Name="Winsock Catalog Reset"; Command="netsh winsock reset"; Critical=$true; RequiresRestart=$true},
        @{Name="TCP/IP Stack Reset"; Command="netsh int ip reset"; Critical=$true; RequiresRestart=$true},
        @{Name="IPv6 Stack Reset"; Command="netsh int ipv6 reset"; Critical=$true; RequiresRestart=$true},
        @{Name="HTTP Proxy Reset"; Command="netsh winhttp reset proxy"; Critical=$false; RequiresRestart=$false}
    )
    
    $results = @{
        Successful = 0
        Failed = 0
        Total = $resetOperations.Count
        RequiresRestart = $false
        Operations = @()
    }
    
    foreach ($operation in $resetOperations) {
        $operationResult = @{
            Name = $operation.Name
            Success = $false
            Output = ""
            Error = ""
            Duration = 0
        }
        
        try {
            Write-SecureLog "Executing: $($operation.Name)..." "INFO"
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            $output = cmd /c $operation.Command 2>&1
            $stopwatch.Stop()
            
            $operationResult.Duration = $stopwatch.ElapsedMilliseconds
            $operationResult.Output = $output -join "`n"
            
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
                $operationResult.Success = $true
                $results.Successful++
                Write-SecureLog "$($operation.Name) completed successfully ($($operationResult.Duration)ms)" "SUCCESS"
                
                if ($operation.RequiresRestart) {
                    $results.RequiresRestart = $true
                }
            } else {
                $results.Failed++
                $operationResult.Error = "Exit code: $LASTEXITCODE"
                Write-SecureLog "$($operation.Name) completed with warnings (Exit code: $LASTEXITCODE)" "WARNING"
            }
            
        } catch {
            $results.Failed++
            $operationResult.Error = $_.Exception.Message
            Write-SecureLog "$($operation.Name) failed: $($_.Exception.Message)" "ERROR"
        }
        
        $results.Operations += $operationResult
        Start-Sleep -Milliseconds 500
    }
    
    # Restart network services
    Write-SecureLog "`n--- RESTARTING NETWORK SERVICES ---" "HEADER"
    foreach ($serviceName in $Global:Config.RequiredServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            if ($service.Status -eq "Running") {
                Write-SecureLog "Restarting service: $($service.DisplayName)" "INFO"
                Restart-Service -Name $serviceName -Force -ErrorAction Stop
                Write-SecureLog "Service restarted successfully: $($service.DisplayName)" "SUCCESS"
            } else {
                Write-SecureLog "Starting service: $($service.DisplayName)" "INFO"
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-SecureLog "Service started successfully: $($service.DisplayName)" "SUCCESS"
            }
        } catch {
            Write-SecureLog "Failed to restart service $serviceName`: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Summary
    Write-SecureLog "`n--- RESET SUMMARY ---" "HEADER"
    Write-SecureLog "Operations completed: $($results.Successful)/$($results.Total)" "INFO"
    Write-SecureLog "Failed operations: $($results.Failed)" $(if($results.Failed -gt 0){"WARNING"}else{"INFO"})
    Write-SecureLog "Restart required: $($results.RequiresRestart)" "INFO"
    
    if ($results.RequiresRestart -and -not $NoRestart -and -not $Silent) {
        Write-Host "`nA system restart is required for all changes to take effect." -ForegroundColor Cyan
        $restart = Read-Host "Would you like to restart now? (yes/no)"
        if ($restart -eq "yes") {
            Write-SecureLog "Initiating system restart..." "INFO"
            Restart-Computer -Force
        } else {
            Write-SecureLog "Please restart your computer manually to complete the network reset" "WARNING"
        }
    }
    
    return $results
}

# Utility function for retry logic
function Invoke-WithRetry {
    param(
        [ScriptBlock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 1
    )
    
    $attempt = 1
    do {
        try {
            return & $ScriptBlock
        } catch {
            if ($attempt -eq $MaxRetries) {
                throw
            }
            Write-SecureLog "Attempt $attempt failed, retrying in $DelaySeconds seconds..." "WARNING"
            Start-Sleep -Seconds $DelaySeconds
            $attempt++
        }
    } while ($attempt -le $MaxRetries)
}

# Interactive menu system
function Show-InteractiveMenu {
    do {
        Clear-Host
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║              Network Analysis & Reset Tool v$($Global:Config.Version)              ║" -ForegroundColor Cyan
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║  1. Network Information Analysis                             ║" -ForegroundColor White
        Write-Host "║  2. Network Speed Test                                       ║" -ForegroundColor White
        Write-Host "║  3. Comprehensive Diagnostics                                ║" -ForegroundColor White
        Write-Host "║  4. Network Reset (Requires Admin)                          ║" -ForegroundColor White
        Write-Host "║  5. Full Analysis (All Tests)                               ║" -ForegroundColor White
        Write-Host "║  6. View Log File                                            ║" -ForegroundColor White
        Write-Host "║  7. Export Report                                            ║" -ForegroundColor White
        Write-Host "║  8. Exit                                                     ║" -ForegroundColor White
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Current Status:" -ForegroundColor Yellow
        Write-Host "  Log File: $Global:LogFile" -ForegroundColor Gray
        Write-Host "  Admin Rights: $(if((Test-ExecutionSecurity).IsAdmin){'Yes'}else{'No'})" -ForegroundColor Gray
        Write-Host ""
        
        $choice = Read-Host "Select an option (1-8)"
        
        switch ($choice) {
            "1" {
                Clear-Host
                Get-NetworkInformation | Out-Null
                Pause
            }
            "2" {
                Clear-Host
                Test-NetworkSpeed | Out-Null
                Pause
            }
            "3" {
                Clear-Host
                Start-NetworkDiagnostics | Out-Null
                Pause
            }
            "4" {
                Clear-Host
                Start-NetworkReset | Out-Null
                Pause
            }
            "5" {
                Clear-Host
                Write-SecureLog "Starting full network analysis..." "HEADER"
                Get-NetworkInformation | Out-Null
                Test-NetworkSpeed | Out-Null
                Start-NetworkDiagnostics | Out-Null
                Write-SecureLog "Full analysis completed" "SUCCESS"
                Pause
            }
            "6" {
                if (Test-Path $Global:LogFile) {
                    notepad.exe $Global:LogFile
                } else {
                    Write-Host "Log file not found: $Global:LogFile" -ForegroundColor Red
                    Pause
                }
            }
            "7" {
                Export-Report
                Pause
            }
            "8" {
                Write-SecureLog "Exiting Network Tool..." "INFO"
                break
            }
            default {
                Write-Host "Invalid option. Please select 1-8." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        
    } while ($choice -ne "8")
}

# Report export functionality
function Export-Report {
    try {
        $reportPath = Join-Path (Split-Path $Global:LogFile) "NetworkReport_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').html"
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Network Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Analysis Report</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>Tool Version: $($Global:Config.Version)</p>
    </div>
    
    <div class="section">
        <h2>Log Contents</h2>
        <pre>$(Get-Content $Global:LogFile -Raw -ErrorAction SilentlyContinue)</pre>
    </div>
</body>
</html>
"@
        
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Write-SecureLog "Report exported to: $reportPath" "SUCCESS"
        
        $openReport = Read-Host "Open report in browser? (y/n)"
        if ($openReport -eq 'y' -or $openReport -eq 'Y') {
            Start-Process $reportPath
        }
        
    } catch {
        Write-SecureLog "Failed to export report: $($_.Exception.Message)" "ERROR"
    }
}

# Pause function for interactive mode
function Pause {
    if (-not $Silent) {
        Write-Host "`nPress any key to continue..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Main execution block
try {
    # Initialize logging
    $Global:LogFile = Initialize-Logging -LogDirectory $LogPath
    Write-SecureLog "Network Analysis and Reset Tool v$($Global:Config.Version) started" "HEADER"
    
    # Load configuration file if specified
    if ($ConfigFile) {
        try {
            $customConfig = Get-Content $ConfigFile | ConvertFrom-Json
            foreach ($key in $customConfig.PSObject.Properties.Name) {
                $Global:Config[$key] = $customConfig.$key
            }
            Write-SecureLog "Configuration loaded from: $ConfigFile" "SUCCESS"
        } catch {
            Write-SecureLog "Failed to load configuration file: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Security validation
    $securityCheck = Test-ExecutionSecurity
    if (-not $securityCheck.Safe -and -not $Silent) {
        Write-Host "Security issues detected. Continue anyway? (y/n): " -NoNewline -ForegroundColor Yellow
        $continue = Read-Host
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            Write-SecureLog "Execution cancelled due to security concerns" "INFO"
            exit 1
        }
    }
    
    # Execute based on mode
    switch ($Mode) {
        "Info" {
            Get-NetworkInformation | Out-Null
        }
        "Diagnostic" {
            Start-NetworkDiagnostics | Out-Null
        }
        "Reset" {
            Start-NetworkReset | Out-Null
        }
        "SpeedTest" {
            Test-NetworkSpeed | Out-Null
        }
        "Full" {
            Write-SecureLog "Starting comprehensive network analysis..." "HEADER"
            Get-NetworkInformation | Out-Null
            Test-NetworkSpeed | Out-Null
            Start-NetworkDiagnostics | Out-Null
            Write-SecureLog "Comprehensive analysis completed" "SUCCESS"
        }
        "Menu" {
            Show-InteractiveMenu
        }
    }
    
} catch {
    Write-SecureLog "Critical error in main execution: $($_.Exception.Message)" "ERROR"
    Write-SecureLog "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    
    if (-not $Silent) {
        Write-Host "`nA critical error occurred. Check the log file for details." -ForegroundColor Red
        Write-Host "Log file: $Global:LogFile" -ForegroundColor Yellow
        Pause
    }
    exit 1
    
} finally {
    Write-SecureLog "Network Tool execution completed" "INFO"
    Write-SecureLog "Log file location: $Global:LogFile" "INFO"
    
    if (-not $Silent -and $Mode -ne "Menu") {
        Write-Host "`nExecution completed. Log saved to:" -ForegroundColor Green
        Write-Host $Global:LogFile -ForegroundColor Yellow
        Pause
    }
}