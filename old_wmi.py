#!/usr/bin/env python3
# Copyright (c) 2015 David Lundgren
#
# Python WMI Client
# https://github.com/dlundgren/py-wmi-client
#
# Can be used in place of wmic when using check_wmi_plus.pl with Nagios.
#
# @author David Lundgren (@drlundgren)
#
# The MIT License (MIT)
#
# Copyright (c) 2015 David Lundgren
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# From NEMS Linux's perspective, big thanks to Andrew Bartlett from the Samba
# team for directing me to this script, removing our dependency on the old,
# unsupported Samba version.
#
# 1.6.6 - Upgraded to Python 3 -Robbie Ferguson // NEMS Linux
#

import argparse
import re
import sys
import configparser
import io

from natsort import natsorted, ns
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection

APP_VERSION = '1.6.6'


class WmiClient(object):
    """WMI Client"""

    def __init__(self, auth, host):
        """
        :param auth: Dictionary with keys 'username', 'password', 'domain'
        :param host: Hostname or IP of the target
        """
        self.auth = auth
        self.host = host

    def get_language(self, lang):
        """
        Retrieve the language passed in from int to string

        :param lang: string
        :return: language string
        """
        if lang == 552:
            return 'en-US'
        return '??-??'

    def format_value(self, value, cimtype, type):
        """
        Formats the value based on the cimtype and type

        :param value:
        :param cimtype: string
        :param type: int
        :return: formatted string
        """
        if cimtype == 'string':
            if value == 0:
                return '(null)'
            else:
                return str(value).strip()
        elif cimtype == 'boolean':  # boolean
            if value == 'True':
                return 'True'
            else:
                return 'False'
        elif value is None:
            if cimtype == 'uint32' or cimtype == 'uint64':
                return '0'
        else:
            return ('%s' % value).strip()

    def print_results(self, queryObject, delimiter):
        """
        Prints the results in the classObject as wmic.c would

        :param queryObject: IEnumWbemClassObject
        :param delimiter: string delimiter for output columns
        """
        while True:
            try:
                classObject = queryObject.Next(0xffffffff, 1)[0]
                print('CLASS: %s' % classObject.getClassName())
                record = classObject.getProperties()
                keys = []
                for name in record:
                    keys.append(name.strip())
                keys = natsorted(keys, alg=ns.IGNORECASE)
                print(delimiter.join(keys))
                tmp = []
                for key in keys:
                    if key == 'MUILanguages':
                        vals = []
                        for v in record[key]['value']:
                            vals.append(self.get_language(v))
                        record[key]['value'] = vals

                    if isinstance(record[key]['value'], list):
                        values = []
                        for v in record[key]['value']:
                            values.append(
                                self.format_value(v, record[key]['qualifiers']['CIMTYPE'], record[key]['type']))
                        tmp.append('(%s)' % ','.join(values))
                    else:
                        tmp.append('%s' % self.format_value(record[key]['value'],
                                                              record[key]['qualifiers']['CIMTYPE'],
                                                              record[key]['type']))
                print(delimiter.join(tmp))
            except Exception as e:
                if e.get_error_code() != wmi.WBEMSTATUS.WBEM_S_FALSE:
                    raise
                else:
                    break

    def query_and_print(self, wql, **kwargs):
        """
        Executes the WMI query and prints the results.

        :param wql: WMI Query string
        :param kwargs: Optional parameters, e.g., namespace and delimiter
        """
        namespace = '//./root/cimv2'
        delimiter = '|'
        conn = None
        classObject = None
        wmiService = None
        wmiLogin = None

        if 'namespace' in kwargs:
            namespace = kwargs['namespace']
        if 'delimiter' in kwargs:
            delimiter = kwargs['delimiter']

        try:
            conn = DCOMConnection(self.host, self.auth['username'], self.auth['password'], self.auth['domain'], '', '',
                                  None, oxidResolver=True, doKerberos=False)
            wmiInterface = conn.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            wmiLogin = wmi.IWbemLevel1Login(wmiInterface)
            wmiService = wmiLogin.NTLMLogin(namespace, NULL, NULL)
            wmiLogin.RemRelease()

            queryObject = wmiService.ExecQuery(wql.strip('\n'),
                                               wmi.WBEM_FLAG_RETURN_IMMEDIATELY | wmi.WBEM_FLAG_ENSURE_LOCATABLE)
            self.print_results(queryObject, delimiter)
            queryObject.RemRelease()

            wmiService.RemRelease()
            conn.disconnect()
        except Exception as e:
            if classObject is not None:
                classObject.RemRelease()
            if wmiLogin is not None:
                wmiLogin.RemRelease()
            if wmiService is not None:
                wmiService.RemRelease()
            if conn is not None:
                conn.disconnect()
            raise Exception("Could not connect to %s: %s" % (self.host, str(e)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="WMI Client")
    # Fixed help string using a raw string literal to prevent invalid escape sequences
    parser.add_argument('-U', '--user', dest='user', help=r"[DOMAIN\]USERNAME[%%PASSWORD]")
    parser.add_argument('-A', '--authentication-file', dest='authfile', help="Authentication file")
    parser.add_argument('--delimiter', default='|', help="delimiter, default: |")
    parser.add_argument('--namespace', default='//./root/cimv2', help='namespace name (default //./root/cimv2)')
    parser.add_argument('host', metavar="//host")
    parser.add_argument('wql', metavar="query")
    parser.add_argument('--version', '-v', action="version", version="wmic-1.6.1-nemslinux")

    options = parser.parse_args()

    auth = {
        'username': '',
        'password': '',
        'domain': ''
    }
    if options.authfile is not None:
        authfile = '[root]\n' + open(options.authfile, 'r').read()
        config = configparser.ConfigParser()
        config.read_file(io.StringIO(authfile))
        auth['domain'] = config.get('root', 'domain')
        auth['username'] = config.get('root', 'username')
        auth['password'] = config.get('root', 'password')
    elif options.user is not None:
        m = re.compile(r'(?:(?:([^/\\%]*)[/\\])?([^%]*))(?:%(.*))?').match(options.user)
        auth['domain'], auth['username'], auth['password'] = m.groups('')
    else:
        print("Missing user information")
        sys.exit(1)

    if auth['domain'] == '':
        auth['domain'] = 'WORKGROUP'

    # options.host is expected to start with "//", so we remove the first two characters
    WmiClient(auth, options.host[2:]).query_and_print(options.wql, namespace=options.namespace,
                                                      delimiter=options.delimiter)
