#!/usr/bin/env python3

import argparse
from pysnmp.hlapi import *
import sys

# Correct F5 SNMP OIDs
OIDS = {
    "sysAttrFailoverUnitMask":        "1.3.6.1.4.1.3375.2.1.14.3.1.0",  # Numeric
    "sysAttrFailoverUnitMaskString":  "1.3.6.1.4.1.3375.2.1.14.3.2.0",  # String
    "sysAttrConfigsyncState":         "1.3.6.1.4.1.3375.2.1.14.1.1.0",  # Numeric
    "sysAttrConfigsyncStateString":   "1.3.6.1.4.1.3375.2.1.14.1.2.0",  # String
}

# Mappings
CONFIGSYNC_MAP = {
    "0": "Unknown",
    "1": "Not Configured",
    "2": "Not In Sync",
    "3": "In Sync"
}
FAILOVER_MAP = {
    "0": "Unknown",
    "3": "Standby",
    "4": "Active"
}

def snmp_get_bulk(host, community, oids):
    result = {}
    g = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((host, 161), timeout=2, retries=1),
        ContextData(),
        *[ObjectType(ObjectIdentity(oid)) for oid in oids]
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(g)

    if errorIndication:
        print(f"UNKNOWN - SNMP error: {errorIndication}")
        sys.exit(3)
    elif errorStatus:
        print(f"UNKNOWN - SNMP error: {errorStatus.prettyPrint()}")
        sys.exit(3)
    else:
        for varBind in varBinds:
            oid, value = varBind
            result[str(oid)] = value.prettyPrint()
    return result

def normalize_input(state_input, mapping):
    # Accept either a numeric string or friendly label
    if state_input in mapping.values():
        return state_input
    elif state_input in mapping:
        return mapping[state_input]
    else:
        return None

def main():
    parser = argparse.ArgumentParser(description="Check F5 BigIP Failover and ConfigSync State via SNMP")
    parser.add_argument("-H", "--hostname", required=True, help="Target F5 hostname or IP")
    parser.add_argument("-c", "--community", required=True, help="SNMP community string")
    parser.add_argument("-s", "--syncstate", required=True, help="Expected config sync state (name or code)")
    parser.add_argument("-m", "--machinestate", required=True, help="Expected machine state (name or code)")
    args = parser.parse_args()

    # Normalize user inputs
    expected_sync = normalize_input(args.syncstate, CONFIGSYNC_MAP)
    expected_failover = normalize_input(args.machinestate, FAILOVER_MAP)

    if expected_sync is None:
        print(f"UNKNOWN - Invalid sync state: '{args.syncstate}'. Valid values: {list(CONFIGSYNC_MAP.values()) + list(CONFIGSYNC_MAP.keys())}")
        sys.exit(3)
    if expected_failover is None:
        print(f"UNKNOWN - Invalid machine state: '{args.machinestate}'. Valid values: {list(FAILOVER_MAP.values()) + list(FAILOVER_MAP.keys())}")
        sys.exit(3)

    # Fetch SNMP data
    snmp_data = snmp_get_bulk(args.hostname, args.community, list(OIDS.values()))

    sync_str = snmp_data.get(OIDS["sysAttrConfigsyncStateString"], "unknown")
    sync_num = snmp_data.get(OIDS["sysAttrConfigsyncState"], "unknown")
    failover_str = snmp_data.get(OIDS["sysAttrFailoverUnitMaskString"], "unknown")
    failover_num = snmp_data.get(OIDS["sysAttrFailoverUnitMask"], "unknown")

    # Match logic
    sync_match = expected_sync == sync_str or expected_sync == CONFIGSYNC_MAP.get(sync_num)
    failover_match = expected_failover == failover_str or expected_failover == FAILOVER_MAP.get(failover_num)

    perf_data = f"sync_state=\"{sync_str}\" machine_state=\"{failover_str}\""

    if sync_match and failover_match:
        print(f"OK - F5 SyncState: {sync_str}, MachineState: {failover_str} | {perf_data}")
        sys.exit(0)
    else:
        print(f"CRITICAL - F5 SyncState: {sync_str} (expected: {expected_sync}), "
              f"MachineState: {failover_str} (expected: {expected_failover}) | {perf_data}")
        sys.exit(2)

if __name__ == "__main__":
    main()

