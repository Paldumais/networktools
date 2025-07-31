# networktools
 Professional Network Analysis &amp; Reset Tool

A comprehensive, enterprise-grade PowerShell tool for network troubleshooting, analysis, and reset operations. Designed for IT professionals who need reliable network diagnostics and automated repair capabilities.

✨ Features

🔍 Network Analysis

- Detailed Adapter Information: IP addresses, MAC addresses, connection speeds, and status
- DNS Configuration Analysis: Server addresses, resolution testing, and validation
- Routing Table Inspection: Default gateways, route metrics, and path analysis
- Active Connection Monitoring: Real-time connection tracking and statistics
- Network Performance Metrics: Bandwidth usage, packet statistics, and error rates

🚀 Speed Testing

- Multi-Server Download Tests: Accurate bandwidth measurement using multiple test servers
- Latency Analysis: Comprehensive ping tests to major DNS providers (Google, Cloudflare, Quad9)
- Connection Quality Assessment: Packet loss detection and jitter analysis
- Historical Performance Tracking: Speed test results logging and comparison

🔧 Network Reset Operations

- DNS Cache Management: Flush and rebuild DNS resolver cache
- IP Configuration Reset: Release, renew, and reconfigure network adapters
- Winsock Catalog Repair: Reset network protocol stack to default state
- TCP/IP Stack Restoration: Complete network stack rebuild
- Service Management: Restart critical network services automatically
- Registry Cleanup: Safe network-related registry repairs

🛡️ Security & Stability

- Execution Security Validation: Policy checks and privilege verification
- Secure Logging: Protected log files with proper permissions
- Error Recovery: Robust error handling with automatic fallback methods
- Admin Rights Detection: Automatic privilege escalation when required
- Safe Operation Mode: Non-destructive analysis options

📊 Professional Reporting

- Comprehensive Logging: Detailed operation logs with timestamps
- HTML Report Generation: Professional reports for documentation
- Before/After Comparisons: Network state analysis and improvement tracking
- Export Capabilities: Multiple output formats for integration

🚀 Quick Start

Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges (for reset operations)

Installation

	# Clone the repository
	git clone https://github.com/yourusername/network-tool.git
	cd network-tool
	
	# Run the tool
	.\NetworkTool.ps1

Basic Usage

	# Interactive menu (recommended for beginners)
	.\NetworkTool.ps1
	
	# Network information only
	.\NetworkTool.ps1 -Mode Info
	
	# Speed test only
	.\NetworkTool.ps1 -Mode SpeedTest
	
	# Full analysis (info + speed + diagnostics)
	.\NetworkTool.ps1 -Mode Full
	
	# Network reset (requires admin)
	.\NetworkTool.ps1 -Mode Reset
	
	# Silent operation for automation
	.\NetworkTool.ps1 -Mode Full -Silent

📋 Command Line Parameters

Parameter	Type	Description	Example
-Mode	String	Operation mode: Info, Diagnostic, Reset, SpeedTest, Full, Menu	-Mode Full
-LogPath	String	Custom log directory path	-LogPath "C:\NetworkLogs"
-Silent	Switch	Run without user interaction	-Silent
-NoRestart	Switch	Skip restart prompts	-NoRestart
-ConfigFile	String	Path to JSON configuration file	-ConfigFile "config.json"

🔧 Advanced Configuration


Create a config.json file to customize tool behavior:


	{
	    "MaxLogSize": "10MB",
	    "MaxLogFiles": 5,
	    "TimeoutSeconds": 30,
	    "RetryAttempts": 3,
	    "SpeedTestUrls": [
	        "http://speedtest.ftp.otenet.gr/files/test1Mb.db",
	        "http://speedtest.ftp.otenet.gr/files/test10Mb.db"
	    ],
	    "PingTargets": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
	    "RequiredServices": ["Dhcp", "Dnscache", "Winmgmt", "Netman", "NlaSvc"]
	}

📊 Sample Output

	=== NETWORK INFORMATION ANALYSIS ===
	🟢 Ethernet
	  Type: Intel(R) Ethernet Connection
	  MAC: 00:1B:21:3A:4F:8C
	  Speed: 1 Gbps
	  IPv4: 192.168.1.100/24
	  Gateway: 192.168.1.1
	  DNS: 8.8.8.8, 1.1.1.1
	
	--- CONNECTIVITY ANALYSIS ---
	Connectivity to 8.8.8.8: SUCCESS
	Connectivity to 1.1.1.1: SUCCESS
	
	=== NETWORK SPEED ANALYSIS ===
	Average Download Speed: 95.4 Mbps
	Latency to 8.8.8.8: Avg=12ms, Min=10ms, Max=15ms

🛠️ Use Cases

IT Professionals

- Network troubleshooting and diagnostics
- Automated network health checks
- Documentation and reporting
- Bulk network resets across multiple systems

System Administrators

- Server network configuration validation
- Performance monitoring and optimization
- Incident response and recovery
- Compliance reporting and auditing

Help Desk Technicians

- Quick network issue resolution
- User connectivity troubleshooting
- Standardized diagnostic procedures
- Remote network analysis

Network Engineers

- Infrastructure performance analysis
- Capacity planning and optimization
- Network security assessment
- Change management validation

🔒 Security Considerations

- Privilege Escalation: Tool automatically requests admin rights when needed
- Execution Policy: Validates PowerShell execution policy before running
- Secure Logging: Log files are created with restricted permissions
- Input Validation: All user inputs are validated and sanitized
- Safe Operations: Non-destructive analysis modes available

🤝 Contributing


We welcome contributions! Please see our Contributing Guidelines for details.

Development Setup

	# Fork the repository
	# Clone your fork
	git clone https://github.com/yourusername/network-tool.git
	
	# Create a feature branch
	git checkout -b feature/your-feature-name
	
	# Make your changes and test
	# Submit a pull request

📝 License


This project is licensed under the MIT License - see the LICENSE file for details.

🐛 Bug Reports & Feature Requests


Please use the GitHub Issues page to report bugs or request features.

🏆 Acknowledgments

- Thanks to the PowerShell community for inspiration and best practices
- Network testing infrastructure provided by various speed test services
- Contributors and beta testers who helped improve the tool

---
⭐ If this tool helped you, please consider giving it a star!
