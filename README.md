# wmic-py
Enhanced Python WMI Client for securely querying Windows systems

# Enhanced WMI Client - Setup and Usage Guide

This guide will help you set up and use the Enhanced WMI Client tool for securely querying Windows systems remotely.

## Installation

1. Ensure you have Python 3.x installed:
   ```bash
   python3 --version
   ```

2. Install required dependencies:
   ```bash
   pip3 install impacket natsort configparser
   ```

3. Make the script executable:
   ```bash
   chmod +x wmi_client.py
   ```

## Basic Usage

```bash
python3 wmi_client.py -U 'DOMAIN\Username%Password' //target-hostname "SELECT * FROM Win32_OperatingSystem"
```

## Authentication Options

### 1. Using username/password:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_Process"
```

### 2. With domain:
```bash
python3 wmi_client.py -U 'DOMAIN\User%Password' //192.168.1.27 "SELECT * FROM Win32_Service"
```

### 3. Using authentication file:
Create an auth.txt file with:
```
domain=WORKGROUP
username=Administrator
password=YourPasswordHere
```

Then run:
```bash
python3 wmi_client.py -A auth.txt //192.168.1.27 "SELECT * FROM Win32_LogicalDisk"
```

## Output Formats

### Default formatted output:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_ComputerSystem"
```

### JSON output:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_ComputerSystem" --format json
```

### CSV output:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_ComputerSystem" --format csv --delimiter ','
```

## Additional Options

* `--namespace`: Specify WMI namespace (default: //./root/cimv2)
* `--timeout`: Set connection timeout in seconds (default: 30)
* `--debug`: Enable detailed debug logging
* `--examples`: Show usage examples

## Common WMI Queries

### System Information:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem"
```

### Running Processes:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT Name, ProcessId, ExecutablePath FROM Win32_Process"
```

### Disk Drive Information:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT Caption, DeviceID, Size, FreeSpace FROM Win32_LogicalDisk"
```

### Network Configuration:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT IPAddress, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"
```

### Installed Software:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT Name, Vendor, Version, InstallDate FROM Win32_Product"
```

### User Accounts:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT Name, Status, Disabled, LocalAccount FROM Win32_UserAccount"
```

## Troubleshooting

### Access Denied Issues:
1. Verify credentials are correct
2. Ensure the Remote Procedure Call (RPC) service is running on target
3. Check Windows Firewall settings on target
4. Verify WMI service is running on target

### Connection Timed Out:
1. Check network connectivity with ping
2. Verify required ports are open (135, 445, and dynamic RPC ports)

### Authentication Failure:
1. Double-check username and password
2. Try using fully qualified domain\username format
3. Ensure account is not locked or disabled

### Enable Debug Mode:
For detailed logging to troubleshoot connection issues:
```bash
python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_ComputerSystem" --debug
```

## Security Considerations

* Store credentials securely using authentication files with proper permissions
* Consider using a dedicated service account with limited privileges
* Implement network segmentation to restrict WMI access
* Monitor and audit WMI query activities
* Rotate passwords regularly
