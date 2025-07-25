#!/usr/bin/env python3

import argparse
from pysnmp.hlapi import *
import sys

# OIDs – replace with real ones if needed
OIDS = {
    "sysAttrFailoverUnitMask":        "1.3.6.1.4.1.3375.2.1.1.1.1.2",  # Numeric
    "sysAttrFailoverUnitMaskString":  "1.3.6.1.4.1.3375.2.1.1.1.1.3",  # String
    "sysAttrConfigsyncState":         "1.3.6.1.4.1.3375.2.1.1.1.1.4",  # Numeric
    "sysAttrConfigsyncStateString":   "1.3.6.1.4.1.3375.2.1.1.1.1.5",  # String
}

def snmp_bulkget(host, community, oids):
    results = {}
    g = bulkCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),  # SNMPv2c
        UdpTransportTarget((host, 161)),
        ContextData(),
        0, 10,
        *[ObjectType(ObjectIdentity(oid)) for oid in oids],
        lexicographicMode=False
    )
    for (errorIndication, errorStatus, errorIndex, varBinds) in g:
        if errorIndication:
            print(f"UNKNOWN - SNMP error: {errorIndication}")
            sys.exit(3)
        elif errorStatus:
            print(f"UNKNOWN - SNMP error: {errorStatus.prettyPrint()}")
            sys.exit(3)
        for varBind in varBinds:
            oid, value = varBind
            results[str(oid)] = value.prettyPrint()
    return results

def main():
    parser = argparse.ArgumentParser(description="Check F5 BigIP Failover and Sync State via SNMP")
    parser.add_argument("-h", "--hostname", required=True, help="Target F5 hostname or IP")
    parser.add_argument("-c", "--community", required=True, help="SNMP community string")
    parser.add_argument("-s", "--syncstate", required=True, help="Expected sync state (string or numeric)")
    parser.add_argument("-m", "--machinestate", required=True, help="Expected machine state (string or numeric)")

    args = parser.parse_args()

    oids = list(OIDS.values())
    snmp_data = snmp_bulkget(args.hostname, args.community, oids)

    sync_state_str  = snmp_data.get(OIDS["sysAttrConfigsyncStateString"], "unknown")
    sync_state_num  = snmp_data.get(OIDS["sysAttrConfigsyncState"], "unknown")
    machine_state_str = snmp_data.get(OIDS["sysAttrFailoverUnitMaskString"], "unknown")
    machine_state_num = snmp_data.get(OIDS["sysAttrFailoverUnitMask"], "unknown")

    # Match if either string or numeric matches
    sync_match = args.syncstate == sync_state_str or args.syncstate == sync_state_num
    machine_match = args.machinestate == machine_state_str or args.machinestate == machine_state_num

    perf_data = (
        f"sync_state=\"{sync_state_str}\" "
        f"machine_state=\"{machine_state_str}\""
    )

    if sync_match and machine_match:
        print(f"OK - F5 SyncState: {sync_state_str}, MachineState: {machine_state_str} | {perf_data}")
        sys.exit(0)
    else:
        print(f"CRITICAL - F5 SyncState: {sync_state_str} (expected: {args.syncstate}), "
              f"MachineState: {machine_state_str} (expected: {args.machinestate}) | {perf_data}")
        sys.exit(2)

if __name__ == "__main__":
    main()

