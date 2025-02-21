#!/usr/bin/env python3
# Enhanced WMI Client Tool
# A secure and robust WMI client for querying Windows systems remotely
# Supports authentication, secure connections, and formatted output
#

import argparse
import re
import sys
import os
import configparser
import io
import logging
import socket
import textwrap
from datetime import datetime

try:
    from natsort import natsorted, ns
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
except ImportError:
    print("Error: Required dependencies not found.")
    print("Please install required packages with: pip3 install impacket natsort configparser")
    sys.exit(1)

VERSION = '2.0.1'

class Color:
    """ANSI color codes for terminal output"""
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WmiClient:
    """Enhanced WMI Client for remote Windows system queries"""

    def __init__(self, auth, host, debug=False):
        """
        Initialize the WMI client
        
        Args:
            auth (dict): Authentication information (username, password, domain)
            host (str): Target host address
            debug (bool): Enable debug logging
        """
        self.auth = auth
        self.host = host
        self.debug = debug
        
        if debug:
            logging.basicConfig(level=logging.DEBUG, 
                               format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def get_language(self, lang):
        """
        Retrieve the language from int to string format
        
        Args:
            lang (int): Language code
            
        Returns:
            str: Language identifier
        """
        languages = {
            552: 'en-US',
            1033: 'en-US',
            1031: 'de-DE',
            1036: 'fr-FR',
            1034: 'es-ES',
            1041: 'ja-JP',
            2052: 'zh-CN',
            1049: 'ru-RU'
        }
        return languages.get(lang, f'unknown-{lang}')

    def format_value(self, value, cimtype, type_code):
        """
        Format values based on their CIM type
        
        Args:
            value: Value to format
            cimtype (str): CIM type
            type_code (int): Type code
            
        Returns:
            str: Formatted value
        """
        if value is None:
            if cimtype in ('uint16', 'uint32', 'uint64', 'sint32'):
                return '0'
            return '(null)'
            
        if cimtype == 'string':
            return str(value).strip()
        elif cimtype == 'boolean':
            return 'True' if value else 'False'
        elif cimtype == 'datetime':
            # Format WMI datetime properly
            try:
                # Handle WMI datetime format
                if isinstance(value, str) and value.startswith('20'):
                    year = int(value[0:4])
                    month = int(value[4:6])
                    day = int(value[6:8])
                    hour = int(value[8:10])
                    minute = int(value[10:12])
                    second = int(value[12:14])
                    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
            except (ValueError, IndexError):
                pass
            return str(value).strip()
        else:
            return str(value).strip()

    def print_results(self, query_object, delimiter, output_format='default'):
        """
        Print query results in the specified format
        
        Args:
            query_object: WMI query results
            delimiter (str): Delimiter for output
            output_format (str): Output format (default, json, csv)
        """
        results = []
        headers = []
        
        try:
            while True:
                try:
                    # Get next query result
                    next_result = query_object.Next(0xffffffff, 1)
                    
                    # Check if we have a valid result
                    if not next_result or len(next_result) < 1:
                        break
                        
                    class_object = next_result[0]
                    
                    if output_format == 'default':
                        print(f"{Color.BLUE}CLASS: {class_object.getClassName()}{Color.ENDC}")
                    
                    record = class_object.getProperties()
                    keys = []
                    for name in record:
                        keys.append(name.strip())
                    keys = natsorted(keys, alg=ns.IGNORECASE)
                    
                    # Store or print headers
                    if not headers:
                        headers = keys
                        if output_format == 'default':
                            print(f"{Color.GREEN}{delimiter.join(keys)}{Color.ENDC}")
                        elif output_format == 'csv' and not results:
                            print(delimiter.join(keys))
                    
                    # Process values
                    row = {}
                    tmp = []
                    for key in keys:
                        # Guard against missing keys or malformed records
                        if key not in record:
                            tmp.append("(null)")
                            row[key] = "(null)"
                            continue
                            
                        # Safe handling of qualifiers
                        cimtype = "string"  # Default type
                        if 'qualifiers' in record[key] and 'CIMTYPE' in record[key]['qualifiers']:
                            cimtype = record[key]['qualifiers']['CIMTYPE']
                        
                        # Handle MUI Languages specially
                        if key == 'MUILanguages' and isinstance(record[key].get('value'), list):
                            vals = []
                            for v in record[key]['value']:
                                vals.append(self.get_language(v))
                            record[key]['value'] = vals

                        # Format list values
                        if isinstance(record[key].get('value'), list):
                            values = []
                            for v in record[key]['value']:
                                values.append(self.format_value(v, cimtype, record[key].get('type', 0)))
                            formatted_value = '(' + ','.join(values) + ')'
                        else:
                            # Format scalar value
                            formatted_value = self.format_value(
                                record[key].get('value'), 
                                cimtype,
                                record[key].get('type', 0)
                            )
                        
                        tmp.append(formatted_value)
                        row[key] = formatted_value
                    
                    results.append(row)
                    
                    if output_format == 'default':
                        print(delimiter.join(tmp))
                    elif output_format == 'csv':
                        print(delimiter.join(tmp))
                    
                except Exception as e:
                    if hasattr(e, 'get_error_code') and e.get_error_code() != wmi.WBEMSTATUS.WBEM_S_FALSE:
                        if self.debug:
                            logging.error(f"Error processing result: {str(e)}")
                        print(f"{Color.YELLOW}Warning: {str(e)}{Color.ENDC}")
                    else:
                        if self.debug:
                            logging.error(f"Unexpected error: {str(e)}")
                        # Continue with next result instead of crashing
                        continue
                        
            # JSON output (at the end)
            if output_format == 'json' and results:
                try:
                    import json
                    print(json.dumps(results, indent=2))
                except Exception as e:
                    if self.debug:
                        logging.error(f"JSON formatting error: {str(e)}")
                    print(f"{Color.RED}Error formatting JSON output: {str(e)}{Color.ENDC}")
            
            # Print success message with result count
            if output_format == 'default' and results:
                print("-" * 60)
                print(f"{Color.GREEN}Query completed successfully. Retrieved {len(results)} record(s).{Color.ENDC}")
                
        except Exception as e:
            if self.debug:
                logging.error(f"Error in print_results: {str(e)}")
            print(f"{Color.RED}Error processing results: {str(e)}{Color.ENDC}")

    def query_and_print(self, wql, **kwargs):
        """
        Query WMI and print results
        
        Args:
            wql (str): WMI query
            **kwargs: Additional options
            
        Returns:
            bool: Success status
        """
        namespace = kwargs.get('namespace', '//./root/cimv2')
        delimiter = kwargs.get('delimiter', '|')
        output_format = kwargs.get('output_format', 'default')
        timeout = kwargs.get('timeout', 30)
        
        conn = None
        class_object = None
        wmi_service = None
        wmi_login = None
        
        socket.setdefaulttimeout(timeout)
        
        try:
            if self.debug:
                logging.info(f"Connecting to {self.host}")
                logging.info(f"Using namespace: {namespace}")
                logging.info(f"Query: {wql}")
            
            # Create DCOM connection
            conn = DCOMConnection(
                self.host, 
                self.auth['username'], 
                self.auth['password'], 
                self.auth['domain'], 
                '', '', None, 
                oxidResolver=True, 
                doKerberos=False
            )
            
            # Create WMI interface
            wmi_interface = conn.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            wmi_login = wmi.IWbemLevel1Login(wmi_interface)
            wmi_service = wmi_login.NTLMLogin(namespace, NULL, NULL)
            wmi_login.RemRelease()

            # Execute query and process results
            query_object = wmi_service.ExecQuery(
                wql.strip('\n'),
                wmi.WBEM_FLAG_RETURN_IMMEDIATELY | wmi.WBEM_FLAG_ENSURE_LOCATABLE
            )
            
            self.print_results(query_object, delimiter, output_format)
            query_object.RemRelease()

            wmi_service.RemRelease()
            conn.disconnect()
            
            # Ensure we properly exit after completion
            if kwargs.get('auto_exit', False):
                sys.exit(0)
                
            return True
            
        except Exception as e:
            # Clean up resources
            if class_object is not None:
                class_object.RemRelease()
            if wmi_login is not None:
                wmi_login.RemRelease()
            if wmi_service is not None:
                wmi_service.RemRelease()
            if conn is not None:
                conn.disconnect()
                
            error_message = str(e)
            if "rpc_s_access_denied" in error_message:
                print(f"{Color.RED}Access denied. Please check your credentials and ensure WMI is properly configured on the target.{Color.ENDC}")
                print(f"{Color.YELLOW}Troubleshooting tip: Verify that the Remote Procedure Call (RPC) service is running on the target.{Color.ENDC}")
            elif "STATUS_LOGON_FAILURE" in error_message:
                print(f"{Color.RED}Authentication failure. Please check username and password.{Color.ENDC}")
            elif "timed out" in error_message.lower():
                print(f"{Color.RED}Connection timed out. The host may be unreachable or blocking WMI traffic.{Color.ENDC}")
            else:
                print(f"{Color.RED}Error connecting to {self.host}: {error_message}{Color.ENDC}")
                
            if self.debug:
                logging.error(f"Connection error: {error_message}")
                
            return False

def validate_host(host):
    """Validate and format host address"""
    if not host.startswith('//'):
        return '//' + host
    return host

def load_auth_from_file(file_path):
    """Load authentication from config file"""
    if not os.path.exists(file_path):
        print(f"{Color.RED}Error: Authentication file not found: {file_path}{Color.ENDC}")
        sys.exit(1)
        
    try:
        authfile = '[root]\n' + open(file_path, 'r').read()
        config = configparser.ConfigParser()
        config.read_string(authfile)
        
        auth = {
            'domain': config.get('root', 'domain', fallback='WORKGROUP'),
            'username': config.get('root', 'username'),
            'password': config.get('root', 'password')
        }
        return auth
    except Exception as e:
        print(f"{Color.RED}Error parsing authentication file: {str(e)}{Color.ENDC}")
        sys.exit(1)

def parse_auth_string(auth_string):
    """Parse authentication string to extract domain, username, and password"""
    match = re.compile('(?:(?:([^/\\\\%]*)[/\\\\])?([^%]*))(?:%(.*))?').match(auth_string)
    if not match:
        print(f"{Color.RED}Invalid authentication format. Use: [DOMAIN\\]USERNAME[%PASSWORD]{Color.ENDC}")
        sys.exit(1)
        
    domain, username, password = match.groups('')
    if not username:
        print(f"{Color.RED}Missing username in authentication string{Color.ENDC}")
        sys.exit(1)
        
    return {
        'domain': domain or 'WORKGROUP',
        'username': username,
        'password': password
    }

def show_examples():
    """Display usage examples"""
    examples = """
Examples:
    # Basic query with username/password
    python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_OperatingSystem"
    
    # Query with domain authentication
    python3 wmi_client.py -U 'DOMAIN\\User%Password' //192.168.1.27 "SELECT * FROM Win32_Process"
    
    # Using authentication file
    python3 wmi_client.py -A auth.txt //192.168.1.27 "SELECT * FROM Win32_Service"
    
    # JSON output format
    python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_LogicalDisk" --format json
    
    # CSV output with comma delimiter
    python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_ComputerSystem" --format csv --delimiter ','
    
    # Query with different namespace
    python3 wmi_client.py -U 'Administrator%Password' //192.168.1.27 "SELECT * FROM Win32_Product" --namespace "//./root/cimv2"
    """
    print(examples)

def main():
    parser = argparse.ArgumentParser(
        description=f"Enhanced WMI Client v{VERSION}",
        epilog="For more information and examples, use the --examples flag.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-U', '--user', dest='user', help="[DOMAIN\\]USERNAME[%%PASSWORD]")
    parser.add_argument('-A', '--authentication-file', dest='authfile', help="Authentication file")
    parser.add_argument('--delimiter', default='|', help="Output delimiter, default: |")
    parser.add_argument('--namespace', default='//./root/cimv2', help='Namespace (default: //./root/cimv2)')
    parser.add_argument('--format', choices=['default', 'json', 'csv'], default='default', help='Output format')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds')
    parser.add_argument('--examples', action='store_true', help='Show usage examples')
    parser.add_argument('--version', '-v', action='version', version=f"WMI Client v{VERSION}")
    parser.add_argument('host', metavar="//host", nargs='?', help='Target host address')
    parser.add_argument('wql', metavar="query", nargs='?', help='WMI query')
    
    args = parser.parse_args()
    
    # Show examples if requested
    if args.examples:
        show_examples()
        sys.exit(0)
        
    # Check required arguments
    if not args.host or not args.wql:
        if not args.examples:
            parser.print_help()
            print(f"\n{Color.RED}Error: Missing host and/or query parameters{Color.ENDC}")
            print(f"{Color.YELLOW}Use --examples to see usage examples{Color.ENDC}")
        sys.exit(1)
    
    # Get authentication credentials
    auth = None
    if args.authfile:
        auth = load_auth_from_file(args.authfile)
    elif args.user:
        auth = parse_auth_string(args.user)
    else:
        print(f"{Color.RED}Error: Missing authentication. Use -U or -A options.{Color.ENDC}")
        sys.exit(1)
    
    # Validate and format host
    host = validate_host(args.host)
    
    # Prepare nice output header
    host_str = host[2:]  # Remove // prefix
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Construct the command that was executed
    command_parts = []
    command_parts.append(f"python3 {os.path.basename(sys.argv[0])}")
    
    if args.user:
        command_parts.append(f"-U '{args.user}'")
    elif args.authfile:
        command_parts.append(f"-A {args.authfile}")
        
    if args.delimiter != '|':
        command_parts.append(f"--delimiter '{args.delimiter}'")
        
    if args.namespace != '//./root/cimv2':
        command_parts.append(f"--namespace '{args.namespace}'")
        
    if args.format != 'default':
        command_parts.append(f"--format {args.format}")
        
    if args.debug:
        command_parts.append("--debug")
        
    if args.timeout != 30:
        command_parts.append(f"--timeout {args.timeout}")
        
    command_parts.append(f"//{host_str}")
    command_parts.append(f'"{args.wql}"')
    
    executed_command = " ".join(command_parts)
    
    print(f"{Color.BOLD}=== WMI Query: {current_time} ==={Color.ENDC}")
    print(f"{Color.BOLD}Target: {host_str}{Color.ENDC}")
    print(f"{Color.BOLD}Query: {args.wql}{Color.ENDC}")
    print(f"{Color.YELLOW}Executed Command: {executed_command}{Color.ENDC}")
    print("-" * 60)
    
    # Execute query
    client = WmiClient(auth, host_str, args.debug)
    success = client.query_and_print(
        args.wql,
        namespace=args.namespace,
        delimiter=args.delimiter,
        output_format=args.format,
        timeout=args.timeout,
        auto_exit=not args.debug  # Auto-exit in normal mode, but not in debug mode
    )
    
    # Show status code on exit (will only reach here in debug mode or on failure)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Operation canceled by user{Color.ENDC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Color.RED}Unexpected error: {str(e)}{Color.ENDC}")
        sys.exit(1)