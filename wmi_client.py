#!/usr/bin/env python3
# Python WMI Client
# A direct replacement for the wmic command-line tool
#

import argparse
import re
import sys
import os
import configparser
import io
import socket

try:
    from natsort import natsorted, ns
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
except ImportError:
    print("Error: Required dependencies not found.")
    print("Please install required packages with: pip3 install impacket natsort configparser")
    sys.exit(1)

VERSION = '2.0.2'

class WmiClient:
    """WMI Client that mimics original wmic behavior"""

    def __init__(self, auth, host):
        """
        Initialize the WMI client
        
        Args:
            auth (dict): Authentication information (username, password, domain)
            host (str): Target host address
        """
        self.auth = auth
        self.host = host

    def get_language(self, lang):
        """
        Retrieve the language from int to string format
        
        Args:
            lang (int): Language code
            
        Returns:
            str: Language identifier
        """
        if lang == 552:
            return 'en-US'
        return '??-??'

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
            if value == 0:
                return '(null)'
            else:
                return str(value).strip()
        elif cimtype == 'boolean':
            return 'True' if value else 'False'
        else:
            return str(value).strip()

    def print_results(self, query_object, delimiter):
        """
        Print query results like the original wmic
        
        Args:
            query_object: WMI query results
            delimiter (str): Delimiter for output
        """
        try:
            while True:
                try:
                    # Get next query result
                    next_result = query_object.Next(0xffffffff, 1)
                    
                    # Check if we have a valid result
                    if not next_result or len(next_result) < 1:
                        break
                        
                    class_object = next_result[0]
                    
                    print(f'CLASS: {class_object.getClassName()}')
                    
                    record = class_object.getProperties()
                    keys = []
                    for name in record:
                        keys.append(name.strip())
                    keys = natsorted(keys, alg=ns.IGNORECASE)
                    
                    # Print headers
                    print(delimiter.join(keys))
                    
                    # Process values
                    tmp = []
                    for key in keys:
                        # Guard against missing keys or malformed records
                        if key not in record:
                            tmp.append("(null)")
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
                    
                    # Print values
                    print(delimiter.join(tmp))
                    
                except Exception as e:
                    if hasattr(e, 'get_error_code') and e.get_error_code() != wmi.WBEMSTATUS.WBEM_S_FALSE:
                        raise
                    else:
                        break
                
        except Exception as e:
            print(f"Error processing results: {str(e)}")
            sys.exit(1)

    def query_and_print(self, wql, **kwargs):
        """
        Query WMI and print results
        
        Args:
            wql (str): WMI query
            **kwargs: Additional options
        """
        namespace = kwargs.get('namespace', '//./root/cimv2')
        delimiter = kwargs.get('delimiter', '|')
        timeout = kwargs.get('timeout', 30)
        
        conn = None
        class_object = None
        wmi_service = None
        wmi_login = None
        
        socket.setdefaulttimeout(timeout)
        
        try:
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
            
            self.print_results(query_object, delimiter)
            query_object.RemRelease()

            wmi_service.RemRelease()
            conn.disconnect()
            
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
                print("Access denied. Please check your credentials and ensure WMI is properly configured on the target.")
            elif "STATUS_LOGON_FAILURE" in error_message:
                print("Authentication failure. Please check username and password.")
            elif "timed out" in error_message.lower():
                print("Connection timed out. The host may be unreachable or blocking WMI traffic.")
            else:
                print(f"Error connecting to {self.host}: {error_message}")
                
            sys.exit(1)

def validate_host(host):
    """Validate and format host address"""
    if not host.startswith('//'):
        return '//' + host
    return host

def load_auth_from_file(file_path):
    """Load authentication from config file"""
    if not os.path.exists(file_path):
        print(f"Error: Authentication file not found: {file_path}")
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
        print(f"Error parsing authentication file: {str(e)}")
        sys.exit(1)

def parse_auth_string(auth_string):
    """Parse authentication string to extract domain, username, and password"""
    match = re.compile('(?:(?:([^/\\\\%]*)[/\\\\])?([^%]*))(?:%(.*))?').match(auth_string)
    if not match:
        print("Invalid authentication format. Use: [DOMAIN\\]USERNAME[%PASSWORD]")
        sys.exit(1)
        
    domain, username, password = match.groups('')
    if not username:
        print("Missing username in authentication string")
        sys.exit(1)
        
    return {
        'domain': domain or 'WORKGROUP',
        'username': username,
        'password': password
    }

def main():
    parser = argparse.ArgumentParser(
        description=f"Python WMI Client v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-U', '--user', dest='user', help="[DOMAIN\\]USERNAME[%%PASSWORD]")
    parser.add_argument('-A', '--authentication-file', dest='authfile', help="Authentication file")
    parser.add_argument('--delimiter', default='|', help="Output delimiter, default: |")
    parser.add_argument('--namespace', default='//./root/cimv2', help='Namespace (default: //./root/cimv2)')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds')
    parser.add_argument('--version', '-v', action='version', version=f"WMI Client v{VERSION}")
    parser.add_argument('host', metavar="//host", help='Target host address')
    parser.add_argument('wql', metavar="query", help='WMI query')
    
    args = parser.parse_args()
    
    # Get authentication credentials
    auth = None
    if args.authfile:
        auth = load_auth_from_file(args.authfile)
    elif args.user:
        auth = parse_auth_string(args.user)
    else:
        print("Missing authentication. Use -U or -A options.")
        sys.exit(1)
    
    # Validate and format host
    host = validate_host(args.host)
    host_str = host[2:]  # Remove // prefix
    
    # Execute query
    client = WmiClient(auth, host_str)
    client.query_and_print(
        args.wql,
        namespace=args.namespace,
        delimiter=args.delimiter,
        timeout=args.timeout
    )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation canceled by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)