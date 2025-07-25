#!/usr/bin/env python3
"""
F5 Virtual Server Status Check for Icinga2/Nagios
Converts Perl Check-F5-VirtualServers.pl to Python

This script checks the status of F5 BIG-IP virtual servers via SNMP.
It monitors virtual server availability, connections, and performance metrics.

Author: Converted from Perl original
Usage: check_f5_virtualservers.py -H <host> -C <community> [options]
"""

import sys
import argparse
from pysnmp.hlapi import *
from pysnmp.proto.rfc1902 import Counter32, Counter64, Gauge32, Integer
import re

# Exit codes for Nagios/Icinga2
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

# F5 BIG-IP Virtual Server SNMP OIDs
F5_VS_OID_BASE = "1.3.6.1.4.1.3375.2.2.10"
F5_VS_NAME_OID = f"{F5_VS_OID_BASE}.1.2.1.1"          # ltmVirtualServName
F5_VS_STATUS_OID = f"{F5_VS_OID_BASE}.1.2.1.2"        # ltmVirtualServAvailState
F5_VS_ENABLED_OID = f"{F5_VS_OID_BASE}.1.2.1.3"       # ltmVirtualServEnabledState
F5_VS_REASON_OID = f"{F5_VS_OID_BASE}.1.2.1.5"        # ltmVirtualServStatusReason
F5_VS_CUR_CONNS_OID = f"{F5_VS_OID_BASE}.2.3.1.12"    # ltmVirtualServStatClientCurConns
F5_VS_MAX_CONNS_OID = f"{F5_VS_OID_BASE}.1.2.1.8"     # ltmVirtualServConnectionLimit
F5_VS_BYTES_IN_OID = f"{F5_VS_OID_BASE}.2.3.1.7"      # ltmVirtualServStatClientBytesIn
F5_VS_BYTES_OUT_OID = f"{F5_VS_OID_BASE}.2.3.1.8"     # ltmVirtualServStatClientBytesOut
F5_VS_PKTS_IN_OID = f"{F5_VS_OID_BASE}.2.3.1.9"       # ltmVirtualServStatClientPktsIn
F5_VS_PKTS_OUT_OID = f"{F5_VS_OID_BASE}.2.3.1.10"     # ltmVirtualServStatClientPktsOut

# Status mappings for F5 Virtual Servers
VS_AVAIL_STATES = {
    0: "none",
    1: "green",     # available
    2: "yellow",    # not currently available
    3: "red",       # not available
    4: "blue"       # availability unknown
}

VS_ENABLED_STATES = {
    0: "none",
    1: "enabled",
    2: "disabled",
    3: "disabledbyparent"
}

class F5VirtualServerCheck:
    def __init__(self, args):
        self.host = args.host
        self.community = args.community
        self.port = args.port
        self.timeout = args.timeout
        self.retries = args.retries
        self.vs_name = args.virtualserver
        self.warning_conns = args.warning
        self.critical_conns = args.critical
        self.verbose = args.verbose
        
        self.exit_code = STATE_OK
        self.output_msg = ""
        self.perfdata = []
        
    def snmp_get(self, oid):
        """Get single SNMP value using getCmd (not nextCmd)"""
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((self.host, self.port), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                ignoreNonIncreasingOid=False
            ):
                if errorIndication:
                    raise Exception(f"SNMP error: {errorIndication}")
                elif errorStatus:
                    raise Exception(f"SNMP error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
                else:
                    for varBind in varBinds:
                        return varBind[1]
        except Exception as e:
            if self.verbose:
                print(f"SNMP GET error for OID {oid}: {e}")
            return None
            
    def snmp_walk(self, oid):
        """Walk SNMP tree to get multiple values"""
        results = {}
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(self.community),
                UdpTransportTarget((self.host, self.port), timeout=self.timeout, retries=self.retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                ignoreNonIncreasingOid=False
            ):
                if errorIndication:
                    break
                elif errorStatus:
                    if self.verbose:
                        print(f"SNMP walk error: {errorStatus.prettyPrint()}")
                    break
                else:
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        if not oid_str.startswith(oid):
                            break
                        # Extract index from OID
                        index = oid_str[len(oid):].lstrip('.')
                        results[index] = varBind[1]
        except Exception as e:
            if self.verbose:
                print(f"SNMP WALK error for OID {oid}: {e}")
        return results
        
    def get_vs_info(self, vs_index):
        """Get detailed information for a specific virtual server"""
        vs_info = {}
        
        # Get virtual server name
        name_oid = f"{F5_VS_NAME_OID}.{vs_index}"
        vs_info['name'] = str(self.snmp_get(name_oid) or f"VS_{vs_index}")
        
        # Get availability state
        status_oid = f"{F5_VS_STATUS_OID}.{vs_index}"
        avail_state = self.snmp_get(status_oid)
        vs_info['avail_state'] = int(avail_state) if avail_state is not None else 4
        vs_info['avail_state_str'] = VS_AVAIL_STATES.get(vs_info['avail_state'], "unknown")
        
        # Get enabled state
        enabled_oid = f"{F5_VS_ENABLED_OID}.{vs_index}"
        enabled_state = self.snmp_get(enabled_oid)
        vs_info['enabled_state'] = int(enabled_state) if enabled_state is not None else 0
        vs_info['enabled_state_str'] = VS_ENABLED_STATES.get(vs_info['enabled_state'], "unknown")
        
        # Get status reason
        reason_oid = f"{F5_VS_REASON_OID}.{vs_index}"
        reason = self.snmp_get(reason_oid)
        vs_info['reason'] = str(reason) if reason else "Unknown"
        
        # Get current connections
        cur_conns_oid = f"{F5_VS_CUR_CONNS_OID}.{vs_index}"
        cur_conns = self.snmp_get(cur_conns_oid)
        vs_info['cur_conns'] = int(cur_conns) if cur_conns is not None else 0
        
        # Get connection limit
        max_conns_oid = f"{F5_VS_MAX_CONNS_OID}.{vs_index}"
        max_conns = self.snmp_get(max_conns_oid)
        vs_info['max_conns'] = int(max_conns) if max_conns is not None else 0
        
        # Get traffic statistics
        bytes_in_oid = f"{F5_VS_BYTES_IN_OID}.{vs_index}"
        bytes_in = self.snmp_get(bytes_in_oid)
        vs_info['bytes_in'] = int(bytes_in) if bytes_in is not None else 0
        
        bytes_out_oid = f"{F5_VS_BYTES_OUT_OID}.{vs_index}"
        bytes_out = self.snmp_get(bytes_out_oid)
        vs_info['bytes_out'] = int(bytes_out) if bytes_out is not None else 0
        
        pkts_in_oid = f"{F5_VS_PKTS_IN_OID}.{vs_index}"
        pkts_in = self.snmp_get(pkts_in_oid)
        vs_info['pkts_in'] = int(pkts_in) if pkts_in is not None else 0
        
        pkts_out_oid = f"{F5_VS_PKTS_OUT_OID}.{vs_index}"
        pkts_out = self.snmp_get(pkts_out_oid)
        vs_info['pkts_out'] = int(pkts_out) if pkts_out is not None else 0
        
        return vs_info
        
    def check_virtual_servers(self):
        """Main check function"""
        try:
            # Get all virtual server names
            vs_names = self.snmp_walk(F5_VS_NAME_OID)
            
            if not vs_names:
                self.exit_code = STATE_UNKNOWN
                self.output_msg = f"No virtual servers found on {self.host}"
                return
                
            # If specific VS requested, filter
            if self.vs_name:
                filtered_vs = {}
                for index, name in vs_names.items():
                    if str(name) == self.vs_name or self.vs_name in str(name):
                        filtered_vs[index] = name
                if not filtered_vs:
                    self.exit_code = STATE_UNKNOWN
                    self.output_msg = f"Virtual server '{self.vs_name}' not found"
                    return
                vs_names = filtered_vs
            
            # Check each virtual server
            vs_results = []
            critical_vs = []
            warning_vs = []
            
            for vs_index in vs_names.keys():
                vs_info = self.get_vs_info(vs_index)
                vs_results.append(vs_info)
                
                # Determine status
                vs_status = "OK"
                
                # Check availability state
                if vs_info['avail_state'] == 3:  # red - not available
                    vs_status = "CRITICAL"
                    critical_vs.append(vs_info['name'])
                elif vs_info['avail_state'] == 2:  # yellow - not currently available
                    vs_status = "WARNING" 
                    warning_vs.append(vs_info['name'])
                elif vs_info['avail_state'] == 4:  # blue - unknown
                    vs_status = "WARNING"
                    warning_vs.append(vs_info['name'])
                
                # Check if disabled
                if vs_info['enabled_state'] in [2, 3]:  # disabled
                    vs_status = "WARNING"
                    if vs_info['name'] not in warning_vs:
                        warning_vs.append(vs_info['name'])
                
                # Check connection thresholds
                if self.critical_conns and vs_info['cur_conns'] >= self.critical_conns:
                    vs_status = "CRITICAL"
                    if vs_info['name'] not in critical_vs:
                        critical_vs.append(vs_info['name'])
                elif self.warning_conns and vs_info['cur_conns'] >= self.warning_conns:
                    if vs_status == "OK":
                        vs_status = "WARNING"
                        if vs_info['name'] not in warning_vs:
                            warning_vs.append(vs_info['name'])
                
                # Add performance data
                vs_name_clean = re.sub(r'[^a-zA-Z0-9_-]', '_', vs_info['name'])
                self.perfdata.append(f"'{vs_name_clean}_connections'={vs_info['cur_conns']};{self.warning_conns or ''};{self.critical_conns or ''};0;{vs_info['max_conns'] if vs_info['max_conns'] > 0 else ''}")
                self.perfdata.append(f"'{vs_name_clean}_bytes_in'={vs_info['bytes_in']}c")
                self.perfdata.append(f"'{vs_name_clean}_bytes_out'={vs_info['bytes_out']}c")
                self.perfdata.append(f"'{vs_name_clean}_packets_in'={vs_info['pkts_in']}c")
                self.perfdata.append(f"'{vs_name_clean}_packets_out'={vs_info['pkts_out']}c")
            
            # Determine overall exit code
            if critical_vs:
                self.exit_code = STATE_CRITICAL
            elif warning_vs:
                self.exit_code = STATE_WARNING
            else:
                self.exit_code = STATE_OK
            
            # Build output message
            total_vs = len(vs_results)
            ok_vs = total_vs - len(critical_vs) - len(warning_vs)
            
            status_word = "OK" if self.exit_code == STATE_OK else ("WARNING" if self.exit_code == STATE_WARNING else "CRITICAL")
            
            if self.vs_name and len(vs_results) == 1:
                # Single VS check
                vs = vs_results[0]
                self.output_msg = f"F5 VS {status_word}: {vs['name']} is {vs['avail_state_str']}/{vs['enabled_state_str']} - {vs['cur_conns']} connections"
                if vs['reason'] != "Unknown" and vs['reason'].strip():
                    self.output_msg += f" ({vs['reason']})"
            else:
                # Multiple VS summary
                self.output_msg = f"F5 Virtual Servers {status_word}: {ok_vs} OK, {len(warning_vs)} WARNING, {len(critical_vs)} CRITICAL"
                
                problem_details = []
                for vs in critical_vs:
                    problem_details.append(f"{vs}(CRIT)")
                for vs in warning_vs:
                    problem_details.append(f"{vs}(WARN)")
                
                if problem_details:
                    self.output_msg += f" - Issues: {', '.join(problem_details)}"
                    
        except Exception as e:
            self.exit_code = STATE_UNKNOWN
            self.output_msg = f"F5 Virtual Server check failed: {str(e)}"
            if self.verbose:
                import traceback
                print(f"Exception details: {traceback.format_exc()}")

def main():
    parser = argparse.ArgumentParser(description='Check F5 BIG-IP Virtual Server Status via SNMP')
    parser.add_argument('-H', '--host', required=True, help='Hostname or IP address of F5 device')
    parser.add_argument('-C', '--community', default='public', help='SNMP community string (default: public)')
    parser.add_argument('-p', '--port', type=int, default=161, help='SNMP port (default: 161)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='SNMP timeout in seconds (default: 5)')
    parser.add_argument('-r', '--retries', type=int, default=3, help='SNMP retries (default: 3)')
    parser.add_argument('-v', '--virtualserver', help='Specific virtual server name to check')
    parser.add_argument('-w', '--warning', type=int, help='Warning threshold for current connections')
    parser.add_argument('-c', '--critical', type=int, help='Critical threshold for current connections')
    parser.add_argument('--verbose', action='store_true', help='Verbose output for debugging')
    
    args = parser.parse_args()
    
    # Validate thresholds
    if args.warning and args.critical and args.warning >= args.critical:
        print("ERROR: Warning threshold must be less than critical threshold")
        sys.exit(STATE_UNKNOWN)
    
    # Create and run check
    check = F5VirtualServerCheck(args)
    check.check_virtual_servers()
    
    # Output results on single line
    output = check.output_msg
    if check.perfdata:
        output += f" | {' '.join(check.perfdata)}"
    
    print(output)
    sys.exit(check.exit_code)

if __name__ == "__main__":
    main()
