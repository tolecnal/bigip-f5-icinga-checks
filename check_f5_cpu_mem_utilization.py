#!/usr/bin/env python3

"""
F5 CPU and Memory Utilization Check for Icinga2/Nagios
Converted from Perl script by Jess Portnoy <kernel01@gmail.com>
Original based on http://www.sladder.org/?p=317

Usage: 
  ./check_f5_cpu_mem_utilization.py -H <hostname> -c <community> -w <cpu_warn> -W <cpu_crit> -m <mem_warn> -M <mem_crit>
  ./check_f5_cpu_mem_utilization.py --hostname <hostname> --community <community> --cpu-warn <cpu_warn> --cpu-crit <cpu_crit> --mem-warn <mem_warn> --mem-crit <mem_crit>

Examples:
  ./check_f5_cpu_mem_utilization.py -H 192.168.1.100 -c public -w 80 -W 90 -m 75 -M 85
  ./check_f5_cpu_mem_utilization.py --hostname f5.example.com --community private --cpu-warn 70 --cpu-crit 85 --mem-warn 80 --mem-crit 95

Description: Checks CPU and memory utilization on F5 using SNMP with modern argument parsing
Version: 1.0 (Python conversion with named arguments)
"""

import sys
import time
import argparse
from pysnmp.hlapi import *
from pysnmp.error import PySnmpError

# Nagios/Icinga exit codes
ERRORS = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3
}

# F5 SNMP OIDs
OIDS = {
    'tmmTotalCyl': '1.3.6.1.4.1.3375.2.1.1.2.1.41.0',
    'tmmIdleCyl': '1.3.6.1.4.1.3375.2.1.1.2.1.42.0', 
    'tmmSleepCyl': '1.3.6.1.4.1.3375.2.1.1.2.1.43.0',
    'sysStatMemoryTotal': '1.3.6.1.4.1.3375.2.1.1.2.1.44.0',
    'sysStatMemoryUsed': '1.3.6.1.4.1.3375.2.1.1.2.1.45.0'
}

def snmp_get(host, community, oids, port=161, timeout=10):
    """
    Perform SNMP GET request for multiple OIDs
    Returns dictionary with OID -> value mapping
    """
    results = {}
    
    for oid_name, oid in oids.items():
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=timeout),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                ignoreNonIncreasingOid=True,
                maxRows=1):
                
                if errorIndication:
                    print(f"SNMP Error: {errorIndication}")
                    sys.exit(ERRORS['UNKNOWN'])
                elif errorStatus:
                    print(f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
                    sys.exit(ERRORS['UNKNOWN'])
                else:
                    for varBind in varBinds:
                        results[oid] = int(varBind[1])
                        break
                    break
        except Exception as e:
            print(f"SNMP connection failed to {host}: {e}")
            sys.exit(ERRORS['UNKNOWN'])
    
    return results

def calculate_cpu_utilization(host, community, port=161, timeout=10):
    """
    Calculate F5 TMM CPU utilization by polling twice with 10 second interval
    """
    cpu_oids = {
        'tmmTotalCyl': OIDS['tmmTotalCyl'],
        'tmmIdleCyl': OIDS['tmmIdleCyl'],
        'tmmSleepCyl': OIDS['tmmSleepCyl']
    }
    
    # First poll
    poll_0 = snmp_get(host, community, cpu_oids, port, timeout)
    
    # Wait 10 seconds
    time.sleep(10)
    
    # Second poll
    poll_1 = snmp_get(host, community, cpu_oids, port, timeout)
    
    # Calculate CPU utilization
    total_diff = poll_1[OIDS['tmmTotalCyl']] - poll_0[OIDS['tmmTotalCyl']]
    idle_diff = poll_1[OIDS['tmmIdleCyl']] - poll_0[OIDS['tmmIdleCyl']]
    sleep_diff = poll_1[OIDS['tmmSleepCyl']] - poll_0[OIDS['tmmSleepCyl']]
    
    if total_diff == 0:
        return 0
    
    cpu_util = ((total_diff - (idle_diff + sleep_diff)) / total_diff) * 100
    return round(cpu_util)

def calculate_memory_utilization(host, community, port=161, timeout=10):
    """
    Calculate F5 memory utilization percentage
    """
    mem_oids = {
        'sysStatMemoryTotal': OIDS['sysStatMemoryTotal'],
        'sysStatMemoryUsed': OIDS['sysStatMemoryUsed']
    }
    
    mem_data = snmp_get(host, community, mem_oids, port, timeout)
    
    if mem_data[OIDS['sysStatMemoryTotal']] == 0:
        return 0
    
    mem_util = (mem_data[OIDS['sysStatMemoryUsed']] / mem_data[OIDS['sysStatMemoryTotal']]) * 100
    return round(mem_util)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Check F5 CPU and Memory utilization via SNMP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 192.168.1.100 -c public -w 80 -c 90 -W 75 -C 85
  %(prog)s --hostname f5.example.com --community private --cpu-warn 70 --cpu-crit 85 --mem-warn 80 --mem-crit 95
        """
    )
    
    # Required arguments
    parser.add_argument('-H', '--hostname', 
                       required=True,
                       help='F5 hostname or IP address')
    
    parser.add_argument('-c', '--community',
                       required=True, 
                       help='SNMP community string')
    
    # CPU thresholds
    parser.add_argument('-w', '--cpu-warn',
                       type=int,
                       required=True,
                       metavar='PERCENT',
                       help='CPU warning threshold (percentage)')
    
    parser.add_argument('-W', '--cpu-crit', 
                       type=int,
                       required=True,
                       metavar='PERCENT',
                       help='CPU critical threshold (percentage)')
    
    # Memory thresholds  
    parser.add_argument('-m', '--mem-warn',
                       type=int, 
                       required=True,
                       metavar='PERCENT',
                       help='Memory warning threshold (percentage)')
    
    parser.add_argument('-M', '--mem-crit',
                       type=int,
                       required=True, 
                       metavar='PERCENT',
                       help='Memory critical threshold (percentage)')
    
    # Optional arguments
    parser.add_argument('-p', '--port',
                       type=int,
                       default=161,
                       help='SNMP port (default: 161)')
    
    parser.add_argument('-t', '--timeout',
                       type=int,
                       default=10,
                       help='SNMP timeout in seconds (default: 10)')
    
    parser.add_argument('-v', '--version', 
                       action='version',
                       version='%(prog)s 1.0')
    
    args = parser.parse_args()
    
    # Validate thresholds
    if args.cpu_warn >= args.cpu_crit:
        parser.error("CPU warning threshold must be less than critical threshold")
    
    if args.mem_warn >= args.mem_crit:
        parser.error("Memory warning threshold must be less than critical threshold")
    
    if not (0 <= args.cpu_warn <= 100) or not (0 <= args.cpu_crit <= 100):
        parser.error("CPU thresholds must be between 0 and 100")
        
    if not (0 <= args.mem_warn <= 100) or not (0 <= args.mem_crit <= 100):
        parser.error("Memory thresholds must be between 0 and 100")
    
    return args

def main():
    args = parse_arguments()
    
    host = args.hostname.strip()
    community = args.community.strip()
    cpu_warn = args.cpu_warn
    cpu_crit = args.cpu_crit
    mem_warn = args.mem_warn
    mem_crit = args.mem_crit
    
    try:
        # Get CPU utilization
        cpu_percent = calculate_cpu_utilization(host, community, args.port, args.timeout)
        
        # Get memory utilization
        mem_percent = calculate_memory_utilization(host, community, args.port, args.timeout)
        
        # Determine exit code and messages
        exit_code = ERRORS['OK']
        messages = []
        
        # Check critical thresholds first
        if cpu_percent > cpu_crit:
            messages.append(f"CRITICAL: TMM CPU utilization on {host} is higher than threshold ({cpu_crit}) - {cpu_percent}%")
            exit_code = ERRORS['CRITICAL']
        
        if mem_percent > mem_crit:
            messages.append(f"CRITICAL: TMM Memory utilization on {host} is higher than threshold ({mem_crit}) - {mem_percent}%")
            exit_code = ERRORS['CRITICAL']
        
        # Check warning thresholds (only if not already critical)
        if exit_code != ERRORS['CRITICAL']:
            if cpu_percent > cpu_warn:
                messages.append(f"WARNING: TMM CPU utilization on {host} is higher than threshold ({cpu_warn}) - {cpu_percent}%")
                exit_code = ERRORS['WARNING']
            
            if mem_percent > mem_warn:
                messages.append(f"WARNING: TMM Memory utilization on {host} is higher than threshold ({mem_warn}) - {mem_percent}%")
                exit_code = ERRORS['WARNING']
        
        # If everything is OK
        if exit_code == ERRORS['OK']:
            messages.append(f"OK: TMM CPU on {host} is {cpu_percent}%")
            messages.append(f"OK: TMM Memory utilization on {host} is {mem_percent}%")
        
        # Print all messages
        for message in messages:
            print(message)
        
        # Add performance data for Icinga2/Nagios
        print(f"|cpu={cpu_percent}%;{cpu_warn};{cpu_crit};0;100 memory={mem_percent}%;{mem_warn};{mem_crit};0;100")
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("UNKNOWN: Script interrupted")
        sys.exit(ERRORS['UNKNOWN'])
    except Exception as e:
        print(f"UNKNOWN: Unexpected error - {e}")
        sys.exit(ERRORS['UNKNOWN'])

if __name__ == "__main__":
    main()
