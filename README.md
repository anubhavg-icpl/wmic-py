# Python WMI Client

A robust, cross-platform replacement for the Windows Management Instrumentation Command-line (WMIC) tool. This Python implementation allows you to query and manage Windows systems remotely from any platform that supports Python.

## Features

- **Cross-Platform Compatibility**: Run from Linux, macOS, or any system with Python support
- **Flexible Authentication**: Support for domain credentials and authentication files
- **Secure Communication**: Proper handling of credentials and connections
- **Familiar Syntax**: Similar command structure to the original WMIC tool
- **Robust Error Handling**: Clear error messages for troubleshooting

## Installation

### Prerequisites

- Python 3.x
- Required packages:
  - impacket
  - natsort
  - configparser

### Setup

```bash
# Install required dependencies
pip3 install impacket natsort configparser

# Clone the repository or download the script
git clone https://github.com/anubhavg-icpl/wmic-py.git
cd wmic-py

# Make the script executable
chmod +x wmi_client.py
```

## Basic Usage

### Query System Information

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Caption, Version FROM Win32_OperatingSystem"
```

### List Running Processes

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, ProcessId FROM Win32_Process"
```

### Authentication Options

#### Domain User:

```bash
python3 wmi_client.py -U 'DOMAIN\User%Password' //192.168.1.10 "SELECT * FROM Win32_ComputerSystem"
```

#### Using Authentication File:

Create an auth.txt file:
```
domain=WORKGROUP
username=Administrator
password=YourPasswordHere
```

Then run:
```bash
python3 wmi_client.py -A auth.txt //192.168.1.10 "SELECT * FROM Win32_BIOS"
```

## Common WMI Queries

### System Information

```bash
# Operating System Details
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Caption, Version, BuildNumber, OSArchitecture FROM Win32_OperatingSystem"

# Computer System Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem"

# BIOS Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"
```

### Hardware Information

```bash
# CPU Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor"

# Memory Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT BankLabel, Capacity, Speed FROM Win32_PhysicalMemory"

# Disk Drive Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Caption, Size, MediaType FROM Win32_DiskDrive"

# Logical Disk Information
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT DeviceID, DriveType, Size, FreeSpace FROM Win32_LogicalDisk"
```

### Network Information

```bash
# Network Adapter Configuration
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Description, IPAddress, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"

# Network Adapters
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT NetConnectionID, Name, Speed FROM Win32_NetworkAdapter WHERE NetEnabled=True"
```

### Software and Services

```bash
# Installed Software
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, Vendor, Version, InstallDate FROM Win32_Product"

# Running Services
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, DisplayName, State, StartMode FROM Win32_Service"

# Startup Programs
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Caption, Command, Location FROM Win32_StartupCommand"
```

### User and Security Information

```bash
# User Accounts
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, FullName, Disabled, LocalAccount FROM Win32_UserAccount"

# Groups
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, Description, LocalAccount FROM Win32_Group"

# Group Membership
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT GroupComponent, PartComponent FROM Win32_GroupUser"

# Shares
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, Path, Description FROM Win32_Share"
```

### Event Logs

```bash
# Recent System Events
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT EventCode, TimeGenerated, Message FROM Win32_NTLogEvent WHERE LogFile='System' AND TimeGenerated > '20250101000000.000000-000'"

# Security Events
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT EventCode, TimeGenerated, Message FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode='4624'"
```

### Performance Monitoring

```bash
# CPU Load Percentage
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'"

# Memory Usage
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT AvailableMBytes, CommittedBytes FROM Win32_PerfFormattedData_PerfOS_Memory"

# Disk Performance
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, PercentDiskTime, AvgDiskQueueLength FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk"

# Network Interface Performance
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, BytesReceivedPersec, BytesSentPersec FROM Win32_PerfFormattedData_Tcpip_NetworkInterface"
```

## Advanced WQL Queries

### Using WHERE Clauses

```bash
# Find processes using more than 100MB of memory
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, ProcessId, WorkingSetSize FROM Win32_Process WHERE WorkingSetSize > 104857600"

# Find services that are running
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, DisplayName FROM Win32_Service WHERE State='Running'"

# Find disks with less than 10GB free space
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT DeviceID, FreeSpace FROM Win32_LogicalDisk WHERE FreeSpace < 10737418240"
```

### Using LIKE Operator

```bash
# Find all processes with names starting with 's'
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, ProcessId FROM Win32_Process WHERE Name LIKE 's%'"

# Find services with 'network' in their display name
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, DisplayName FROM Win32_Service WHERE DisplayName LIKE '%network%'"
```

### Using JOIN

```bash
# Join processes with their services
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Process.Name, Service.Name FROM Win32_Process as Process JOIN Win32_Service as Service on Process.ProcessId = Service.ProcessId"
```

## System Administration Tasks

### Get System Uptime

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT LastBootUpTime FROM Win32_OperatingSystem"
```

### Detect Unauthorized Software

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, Vendor FROM Win32_Product WHERE Name LIKE '%unauthorized_software%'"
```

### Find Large Files

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, FileSize FROM CIM_DataFile WHERE FileSize > 104857600 AND Drive='C:'"
```

### Monitor Hot-Fixes/Patches

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"
```

## Security Auditing

### Find Unauthorized User Accounts

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount=True"
```

### Audit Failed Login Attempts

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT TimeGenerated, Message FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode='4625'"
```

### Inspect Autorun Programs

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Caption, Command, User FROM Win32_StartupCommand"
```

### Check for Suspicious Services

```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.10 "SELECT Name, PathName, StartName FROM Win32_Service WHERE StartName='LocalSystem'"
```

## Troubleshooting

### Common Error Messages

#### Access Denied
```
Access denied. Please check your credentials and ensure WMI is properly configured on the target.
```

**Solutions:**
- Verify username and password are correct
- Ensure the account has appropriate permissions
- Check that the Remote Procedure Call (RPC) service is running on the target
- Verify Windows Firewall settings allow WMI traffic (typically ports 135, 445)

#### Authentication Failure
```
Authentication failure. Please check username and password.
```

**Solutions:**
- Double-check username and password
- Try using the fully qualified domain format: `DOMAIN\username`
- Ensure the account is not locked or disabled

#### Connection Timeout
```
Connection timed out. The host may be unreachable or blocking WMI traffic.
```

**Solutions:**
- Verify network connectivity with ping
- Check that required ports are open (135, 445, and dynamic RPC ports)
- Verify the target machine is powered on and operational

### Target Configuration Requirements

- WMI service must be running
- Remote Procedure Call (RPC) service must be running
- Appropriate firewall rules must be in place
- Target account must have sufficient permissions

## Security Considerations

- Store credentials securely using authentication files with proper permissions
- Use least-privilege accounts whenever possible
- Implement network segmentation to restrict WMI access
- Monitor and audit WMI query activities
- Rotate passwords regularly
- Consider using Kerberos authentication in domain environments

## Limitations

- Some WMI classes may be unavailable depending on Windows version
- Complex queries may time out on resource-constrained systems
- Certain administrative tasks may require elevated privileges
- Performance monitoring queries may have higher overhead

## License

MIT License - See LICENSE file for details.

## Acknowledgments

Based on the original py-wmi-client by David Lundgren with enhancements for security, stability, and usability.

## References

- [WMI Reference](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-reference)
- [WQL SQL for WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
- [Impacket Documentation](https://github.com/SecureAuthCorp/impacket)