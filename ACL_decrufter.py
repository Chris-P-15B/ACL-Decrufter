#!/usr/bin/env python3

import re
import ipaddress
import sys
from pathlib import Path

"""
(c) 2022, Chris Perkins
Licence: BSD 3-Clause

Parses IOS XE, NX-OS or EOS ACL output from show access-list command & attempts to de-cruft it by removing
Access Control Entries (ACE) where permit with an overlapping deny, or deny with an overlapping permit is present earlier in the ACL.
Then removes permit/deny with overlapping networks & merges permit/deny for adjacent networks.
Will also remove entries with overlapping port numbers.

Caveats:
1) IPv4 only & understands only a subset of ACL syntax (e.g. no object-groups), remarks & other unparsed lines are left as is.
2) Attempts to minimise the number of ACEs, which may break the logic for chains of deny & permit statements. Test your results!

v1.0 - Added many missing port name to port number mappings.
v0.5 - Tidying.
v0.4 - Added handling remarks/unparsed lines, added removing ACEs where permit overlaps subsequent deny.
v0.3 - Added outputing to subnet mask & wildcard mask notations.
v0.2 - Minor fixes.
v0.1 - Initial development release.
"""

# Subnet / wildcard mask to CIDR prefix length lookup table
SUBNET_MASKS = {
    "128.0.0.0": "1",
    "127.255.255.255": "1",
    "192.0.0.0": "2",
    "63.255.255.255": "2",
    "224.0.0.0": "3",
    "31.255.255.255": "3",
    "240.0.0.0": "4",
    "15.255.255.255": "4",
    "248.0.0.0": "5",
    "7.255.255.255": "5",
    "252.0.0.0": "6",
    "3.255.255.255": "6",
    "254.0.0.0": "7",
    "1.255.255.255": "7",
    "255.0.0.0": "8",
    "0.255.255.255": "8",
    "255.128.0.0": "9",
    "0.127.255.255": "9",
    "255.192.0.0": "10",
    "0.63.255.255": "10",
    "255.224.0.0": "11",
    "0.31.255.255": "11",
    "255.240.0.0": "12",
    "0.15.255.255": "12",
    "255.248.0.0": "13",
    "0.7.255.255": "13",
    "255.252.0.0": "14",
    "0.3.255.255": "14",
    "255.254.0.0": "15",
    "0.1.255.255": "15",
    "255.255.0.0": "16",
    "0.0.255.255": "16",
    "255.255.128.0": "17",
    "0.0.0.127.255": "17",
    "255.255.192.0": "18",
    "0.0.63.255": "18",
    "255.255.224.0": "19",
    "0.0.31.255": "19",
    "255.255.240.0": "20",
    "0.0.15.255": "20",
    "255.255.248.0": "21",
    "0.0.7.255": "21",
    "255.255.252.0": "22",
    "0.0.3.255": "22",
    "255.255.254.0": "23",
    "0.0.1.255": "23",
    "255.255.255.0": "24",
    "0.0.0.255": "24",
    "255.255.255.128": "25",
    "0.0.0.127": "25",
    "255.255.255.192": "26",
    "0.0.0.63": "26",
    "255.255.255.224": "27",
    "0.0.0.31": "27",
    "255.255.255.240": "28",
    "0.0.0.15": "28",
    "255.255.255.248": "29",
    "0.0.0.7": "29",
    "255.255.255.252": "30",
    "0.0.0.3": "30",
    "255.255.255.254": "31",
    "0.0.0.1": "31",
    "255.255.255.255": "32",
    "0.0.0.0": "32",
}

# Port names to port numbers lookup table
PORT_NAMES = {
    "acap": "674",
    "acr-nema": "104",
    "afpovertcp": "548",
    "aol": "5190",
    "arns": "384",
    "asf-rmcp": "623",
    "asip-webadmin": "311",
    "at-rtmp": "201",
    "aurp": "387",
    "auth": "113",
    "bfd": "3784",
    "bfd-echo": "3785",
    "bftp": "152",
    "bgmp": "264",
    "bgp": "179",
    "biff": "512",
    "bootpc": "68",
    "bootps": "67",
    "chargen": "19",
    "cifs": "3020",
    "cisco-tdp": "711",
    "citadel": "504",
    "citrix-ica": "1494",
    "clearcase": "371",
    "cmd": "514",
    "commerce": "542",
    "courier": "530",
    "csnet-ns": "105",
    "ctiqbe": "2748",
    "cvx": "50003",
    "cvx-cluster": "50004",
    "daytime": "13",
    "dhcp-failover2": "847",
    "dhcpv6-client": "546",
    "dhcpv6-server": "547",
    "discard": "9",
    "dnsix": "195",
    "domain": "53",
    "dsp": "33",
    "echo": "7",
    "efs": "520",
    "epp": "700",
    "esro-gen": "259",
    "exec": "512",
    "finger": "79",
    "ftp": "21",
    "ftp-data": "20",
    "ftps": "990",
    "ftps-data": "989",
    "godi": "848",
    "gopher": "70",
    "gre": "47",
    "gtp-c": "2123",
    "gtp-prime": "3386",
    "gtp-u": "2152",
    "h323": "1720",
    "ha-cluster": "694",
    "hostname": "101",
    "hp-alarm-mgr": "383",
    "http": "80",
    "http-alt": "591",
    "http-mgmt": "280",
    "http-rpc-epmap": "593",
    "https": "443",
    "ident": "113",
    "ieee-mms-ssl": "695",
    "imap": "143",
    "imap3": "220",
    "imap4": "143",
    "imaps": "993",
    "ipp": "631",
    "ipx": "213",
    "irc": "194",
    "iris-beep": "702",
    "isakmp": "500",
    "iscsi": "860",
    "isi-gl": "55",
    "iso-tsap": "102",
    "kerberos": "750",
    "kerberos": "88",
    "kerberos-adm": "749",
    "klogin": "543",
    "kpasswd": "464",
    "kshell": "544",
    "l2tp": "1701",
    "la-maint": "51",
    "lanz": "50001",
    "ldap": "389",
    "ldaps": "636",
    "ldp": "646",
    "lmp": "701",
    "login": "513",
    "lotusnotes": "1352",
    "lpd": "515",
    "lsp-ping": "3503",
    "mac-srvr-admin": "660",
    "matip-type-a": "350",
    "matip-type-b": "351",
    "micro-bfd": "6784",
    "microsoft-ds": "445",
    "mlag": "4432",
    "mlag-arp-sync": "50002",
    "mobile-ip": "434",
    "monitor": "561",
    "mpp": "218",
    "msdp": "639",
    "msexch-routing": "691",
    "msg-icp": "29",
    "msp": "18",
    "ms-sql-m": "1434",
    "ms-sql-s": "1433",
    "multihop-bfd": "4784",
    "nameserver": "42",
    "nas": "991",
    "nat": "4532",
    "ncp": "524",
    "netbios-dgm": "138",
    "netbios-ns": "137",
    "netbios-ss": "139",
    "netbios-ssn": "139",
    "netconf-ssh": "830",
    "netrjs-1": "71",
    "netrjs-2": "72",
    "netrjs-3": "73",
    "netrjs-4": "74",
    "netwall": "533",
    "netwnews": "532",
    "new-rwho": "550",
    "nfs": "2049",
    "nntp": "119",
    "nntps": "563",
    "non500-isakmp": "4500",
    "nsw-fe": "27",
    "ntp": "123",
    "odmr": "366",
    "olsr": "698",
    "openvpn": "1194",
    "pcanywhere-data": "5631",
    "pcanywhere-status": "5632",
    "pim-auto-rp": "496",
    "pkix-timestamp": "318",
    "pkt-krb-ipsec": "1293",
    "pop2": "109",
    "pop3": "110",
    "pop3s": "995",
    "pptp": "1723",
    "print-srv": "170",
    "ptp-event": "319",
    "ptp-general": "320",
    "qmtp": "209",
    "qotd": "17",
    "radius": "1645",
    "radius": "1812",
    "radius-acct": "1646",
    "radius-acct": "1813",
    "re-mail-ck": "50",
    "remotefs": "556",
    "repcmd": "641",
    "rip": "520",
    "rje": "5",
    "rlp": "39",
    "rlzdbase": "635",
    "rmc": "657",
    "rmonitor": "560",
    "rpc2portmap": "369",
    "rsh": "514",
    "rsync": "873",
    "rtelnet": "107",
    "rtsp": "554",
    "secureid-udp": "5510",
    "sgmp": "153",
    "silc": "706",
    "sip": "5060",
    "smtp": "25",
    "smux": "199",
    "snagas": "108",
    "snmp": "161",
    "snmptrap": "162",
    "snpp": "444",
    "sqlnet": "1521",
    "sqlserv": "118",
    "sqlsrv": "156",
    "ssh": "22",
    "submission": "587",
    "sunrpc": "111",
    "svrloc": "427",
    "syslog": "514",
    "systat": "11",
    "tacacs": "49",
    "talk": "517",
    "tbrpf": "712",
    "tcpmux": "1",
    "tcpnethaspsrv": "475",
    "telnet": "23",
    "tftp": "69",
    "time": "37",
    "timed": "525",
    "tunnel": "604",
    "ups": "401",
    "uucp": "540",
    "uucp-path": "117",
    "vmnet": "175",
    "vxlan": "4789",
    "who": "513",
    "whois": "43",
    "www": "80",
    "xdmcp": "177",
    "xns-ch": "54",
    "xns-mail": "58",
    "xns-time": "52",
    "z39-50": "210",
}

# ACL operator names lookup table
OPERATOR_NAMES = {
    "eq": "equals",
    "neq": "doesn't equal",
    "lt": "less than",
    "gt": "greater than",
    "range": "between",
}

# Protocol names lookup table
PROTOCOL_NAMES = [
    "ahp",
    "esp",
    "eigrp",
    "gre",
    "icmp",
    "igmp",
    "igrp",
    "ip",
    "ipv4",
    "ipinip",
    "nos",
    "ospf",
    "pim",
    "pcp",
    "tcp",
    "udp",
]


def parse_acl(acl_string):
    """
    Parses the text from show access-list & generates a list of dictionaries representing it.

    Parameters:
    acl_string (str) - ACL text to parse

    Returns:
    acl_list (list of dict) - list of ACE dictionaries
    notation (str) - ACL uses prefix, subnet or wildcard notation
    """
    acl_list = []
    notation = "prefix"
    for line in acl_string.splitlines():
        acl_parts = re.search(
            r"^\s*(\d+)\s+(permit|deny)\s(\w+)\s(\d+\.\d+\.\d+\.\d+|any|host|\d+\.\d+\.\d+\.\d+\/\d+)\s*(\d+\.\d+\.\d+\.\d+)?"
            r"\s*(eq|neq|lt|gt|range)?\s*([\w\-]+|[\w\-]+\s[\w\-]+)?\s*(established|echo|echo\-reply)?\s(\d+\.\d+\.\d+\.\d+|any|host|\d+\.\d+\.\d+\.\d+\/\d+)"
            r"\s*(\d+\.\d+\.\d+\.\d+)?\s*(eq|neq|lt|gt|range)?\s*([\w\-]+|[\w\-]+\s[\w\-]+)?\s*(established|echo|echo\-reply)?"
            r"\s*(log\-input|log)?\s*([\(\[][\w,=:\s]+[\)\]])?$",
            line.lower().rstrip(),
        )
        ace_dict = {
            "line_num": "",
            "action": "",
            "protocol": "",
            "source_network": "",
            "source_network_obj": None,
            "source_operator": "",
            "source_ports": [],
            "source_modifier": "",
            "destination_network": "",
            "destination_network_obj": None,
            "destination_operator": "",
            "destination_ports": [],
            "destination_modifier": "",
            "optional_action": "",
        }

        # For lines that couldn't be parsed, copy them verbatim as a remark
        if not acl_parts:
            acl_parts = re.search(r"^\s*(\d+)\s+(.+)$", line.rstrip())
            if not acl_parts:
                continue
            ace_dict = {
                "line_num": acl_parts.group(1),
                "action": "remark",
                "optional_action": acl_parts.group(2),
            }
        # Parse ACE elements
        else:
            # Parse the Access Control Entry items into a dictionary of ACE elements, then store in a list
            for item in acl_parts.groups():
                item = item if item is not None else ""
                if not ace_dict["line_num"] and re.search(r"^\d+", item):
                    ace_dict["line_num"] = item
                elif not ace_dict["action"] and item in ["permit", "deny"]:
                    ace_dict["action"] = item
                elif not ace_dict["protocol"] and item in PROTOCOL_NAMES:
                    ace_dict["protocol"] = item
                elif not ace_dict["source_network"] and re.search(
                    r"\d+\.\d+\.\d+\.\d+|any|host|\d+\.\d+\.\d+\.\d+\/\d+", item
                ):
                    # For CIDR create IPv4Network object, otherwise handle any, host or subnet mask
                    if "/" in item:
                        ace_dict["source_network"] = item
                        ace_dict["source_network_obj"] = ipaddress.IPv4Network(item)
                    elif item == "any":
                        ace_dict["source_network"] = item
                        ace_dict["source_network_obj"] = ipaddress.IPv4Network(
                            "0.0.0.0/0"
                        )
                    else:
                        ace_dict["source_network"] = item
                elif (
                    ace_dict["source_network"]
                    and not ace_dict["destination_network"]
                    and item in SUBNET_MASKS
                ):
                    # Create IPv4Network object from subnet or wildcard mask
                    ace_dict["source_network"] += f"/{SUBNET_MASKS[item]}"
                    ace_dict["source_network_obj"] = ipaddress.IPv4Network(
                        ace_dict["source_network"]
                    )
                    if item in ([x for x in list(SUBNET_MASKS)[::2]]):
                        notation = "subnet"
                    else:
                        notation = "wildcard"
                elif (
                    ace_dict["source_network"]
                    and ace_dict["source_network"] == "host"
                    and not ace_dict["destination_network"]
                    and re.search(r"\d+\.\d+\.\d+\.\d+", item)
                ):
                    # For host create IPv4Network object
                    ace_dict["source_network"] = f"{item}/32"
                    ace_dict["source_network_obj"] = ipaddress.IPv4Network(
                        ace_dict["source_network"]
                    )
                elif (
                    ace_dict["source_network"]
                    and not ace_dict["destination_network"]
                    and item in OPERATOR_NAMES
                ):
                    ace_dict["source_operator"] = item
                elif (
                    ace_dict["source_operator"]
                    and not ace_dict["source_ports"]
                    and re.search(r"\w+|\w+\s\w+", item)
                ):
                    for port_number in item.split():
                        if port_number in PORT_NAMES:
                            ace_dict["source_ports"].append(
                                int(PORT_NAMES[port_number])
                            )
                        else:
                            ace_dict["source_ports"].append(int(port_number))
                elif (
                    ace_dict["source_network"]
                    and not ace_dict["destination_network"]
                    and item in ["established", "echo", "echo-reply"]
                ):
                    ace_dict["source_modifier"] = item
                elif not ace_dict["destination_network"] and re.search(
                    r"\d+\.\d+\.\d+\.\d+|any|host|\d+\.\d+\.\d+\.\d+\/\d+", item
                ):
                    # For CIDR create IPv4Network object, otherwise handle any, host or subnet mask
                    if "/" in item:
                        ace_dict["destination_network"] = item
                        ace_dict["destination_network_obj"] = ipaddress.IPv4Network(
                            item
                        )
                    elif item == "any":
                        ace_dict["destination_network"] = item
                        ace_dict["destination_network_obj"] = ipaddress.IPv4Network(
                            "0.0.0.0/0"
                        )
                    else:
                        ace_dict["destination_network"] = item
                elif ace_dict["destination_network"] and item in SUBNET_MASKS:
                    # Create IPv4Network object from subnet or wildcard mask
                    ace_dict["destination_network"] += f"/{SUBNET_MASKS[item]}"
                    ace_dict["destination_network_obj"] = ipaddress.IPv4Network(
                        ace_dict["destination_network"]
                    )
                    if item in ([x for x in list(SUBNET_MASKS)[::2]]):
                        notation = "subnet"
                    else:
                        notation = "wildcard"
                elif (
                    ace_dict["destination_network"]
                    and ace_dict["destination_network"] == "host"
                    and re.search(r"\d+\.\d+\.\d+\.\d+", item)
                ):
                    # For host create IPv4Network object
                    ace_dict["destination_network"] = f"{item}/32"
                    ace_dict["destination_network_obj"] = ipaddress.IPv4Network(
                        ace_dict["destination_network"]
                    )
                elif ace_dict["destination_network"] and item in OPERATOR_NAMES:
                    ace_dict["destination_operator"] = item
                elif (
                    ace_dict["destination_operator"]
                    and not ace_dict["destination_ports"]
                    and re.search(r"\w+|\w+\s\w+", item)
                ):
                    for port_number in item.split():
                        if port_number in PORT_NAMES:
                            ace_dict["destination_ports"].append(
                                int(PORT_NAMES[port_number])
                            )
                        else:
                            ace_dict["destination_ports"].append(int(port_number))
                elif ace_dict["destination_network"] and item in [
                    "established",
                    "echo",
                    "echo-reply",
                ]:
                    ace_dict["destination_modifier"] = item
                elif (
                    ace_dict["source_network"]
                    and ace_dict["destination_network"]
                    and item in ["log", "log-input"]
                ):
                    ace_dict["optional_action"] = item

        acl_list.append(ace_dict)

    return acl_list, notation


def check_source_destination_ports_match(ace1, ace2):
    """
    Check ACE source & destination ports/modifiers match, if specified.

    Parameters:
    ace1 (dict) - ACE dictionary
    ace2 (dict) - ACE dictionary

    Returns:
    src_port_match (bool) - whether source ports/modifers match
    dst_port_match (bool) - whether destination ports/modifers match
    """
    src_port_match = False
    dst_port_match = False
    # IP or IPv4 always matches
    if ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4":
        src_port_match = True
        dst_port_match = True
    # No source port operator always matches
    elif not ace1["source_operator"]:
        src_port_match = True
    # Skip if source ports specified on initial ace2, but not the one we're comparing
    elif ace1["source_operator"] and not ace2["source_operator"]:
        src_port_match = False
    # Checks for overlapping source port(s)
    elif ace1["source_operator"] == "eq":
        if ace2["source_operator"] == "eq":
            if ace2["source_ports"][0] == ace1["source_ports"][0]:
                src_port_match = True
    elif ace1["source_operator"] == "neq":
        if ace2["source_operator"] == "neq":
            if ace2["source_ports"][0] == ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "eq":
            if ace2["source_ports"][0] != ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "lt":
            if ace2["source_ports"][0] < ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "gt":
            if ace2["source_ports"][0] > ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "range":
            if (ace2["source_ports"][0] < ace1["source_ports"][0]) and (
                ace2["source_ports"][1] < ace1["source_ports"][0]
            ):
                src_port_match = True
            if (ace2["source_ports"][0] > ace1["source_ports"][0]) and (
                ace2["source_ports"][1] > ace1["source_ports"][0]
            ):
                src_port_match = True
    elif ace1["source_operator"] == "lt":
        if ace2["source_operator"] == "lt":
            if ace2["source_ports"][0] <= ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "eq":
            if ace2["source_ports"][0] < ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "range":
            if (ace2["source_ports"][0] < ace1["source_ports"][0]) and (
                ace2["source_ports"][1] < ace1["source_ports"][0]
            ):
                src_port_match = True
    elif ace1["source_operator"] == "gt":
        if ace2["source_operator"] == "gt":
            if ace2["source_ports"][0] >= ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "eq":
            if ace2["source_ports"][0] > ace1["source_ports"][0]:
                src_port_match = True
        elif ace2["source_operator"] == "range":
            if (ace2["source_ports"][0] > ace1["source_ports"][0]) and (
                ace2["source_ports"][1] > ace1["source_ports"][0]
            ):
                src_port_match = True
    elif ace1["source_operator"] == "range":
        if ace2["source_operator"] == "range":
            if (ace2["source_ports"][0] >= ace1["source_ports"][0]) and (
                ace2["source_ports"][1] <= ace1["source_ports"][1]
            ):
                src_port_match = True
        elif ace2["source_operator"] == "eq":
            if (ace2["source_ports"][0] >= ace1["source_ports"][0]) and (
                ace2["source_ports"][0] <= ace1["source_ports"][1]
            ):
                src_port_match = True

    # Checks for overlapping destination port(s)
    # No destination port operator always matches
    if not ace1["destination_operator"]:
        dst_port_match = True
    # Skip if destination ports specified on initial ace2, but not the one we're comparing
    elif ace1["destination_operator"] and not ace2["destination_operator"]:
        dst_port_match = False
    elif ace1["destination_operator"] == "eq":
        if ace2["destination_operator"] == "eq":
            if ace2["destination_ports"][0] == ace1["destination_ports"][0]:
                dst_port_match = True
    elif ace1["destination_operator"] == "neq":
        if ace2["destination_operator"] == "neq":
            if ace2["destination_ports"][0] == ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "eq":
            if ace2["destination_ports"][0] != ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "lt":
            if ace2["destination_ports"][0] < ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "gt":
            if ace2["destination_ports"][0] > ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "range":
            if (ace2["destination_ports"][0] < ace1["destination_ports"][0]) and (
                ace2["destination_ports"][1] < ace1["destination_ports"][0]
            ):
                dst_port_match = True
            if (ace2["destination_ports"][0] > ace1["destination_ports"][0]) and (
                ace2["destination_ports"][1] > ace1["destination_ports"][0]
            ):
                dst_port_match = True
    elif ace1["destination_operator"] == "lt":
        if ace2["destination_operator"] == "lt":
            if ace2["destination_ports"][0] <= ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "eq":
            if ace2["destination_ports"][0] < ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "range":
            if (ace2["destination_ports"][0] < ace1["destination_ports"][0]) and (
                ace2["destination_ports"][1] < ace1["destination_ports"][0]
            ):
                dst_port_match = True
    elif ace1["destination_operator"] == "gt":
        if ace2["destination_operator"] == "gt":
            if ace2["destination_ports"][0] >= ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "eq":
            if ace2["destination_ports"][0] > ace1["destination_ports"][0]:
                dst_port_match = True
        elif ace2["destination_operator"] == "range":
            if (ace2["destination_ports"][0] > ace1["destination_ports"][0]) and (
                ace2["destination_ports"][1] > ace1["destination_ports"][0]
            ):
                dst_port_match = True
    elif ace1["destination_operator"] == "range":
        if ace2["destination_operator"] == "range":
            if (ace2["destination_ports"][0] >= ace1["destination_ports"][0]) and (
                ace2["destination_ports"][1] <= ace1["destination_ports"][1]
            ):
                dst_port_match = True
        elif ace2["destination_operator"] == "eq":
            if (ace2["destination_ports"][0] >= ace1["destination_ports"][0]) and (
                ace2["destination_ports"][0] <= ace1["destination_ports"][1]
            ):
                dst_port_match = True

    # Check modifiers match, if present (e.g. established)
    if ace1["source_modifier"] != ace2["source_modifier"]:
        src_port_match = False
    if ace1["destination_modifier"] != ace2["destination_modifier"]:
        dst_port_match = False

    return src_port_match, dst_port_match


def check_overlapping_deny_permit(acl_list):
    """
    Iterate through acl_list top down, to remove ACEs where permit with an overlapping deny, or
    deny with an overlapping permit is present earlier in the ACL.

    Parameters:
    acl_list (list of dict) - list of ACE dictionaries

    Returns:
    acl_list2 (list of dict) - remediated list of ACE dictionaries
    """
    acl_list2 = acl_list.copy()
    # Check deny that overlaps subsequent permit
    for count, ace1 in enumerate(acl_list):
        if ace1["action"] == "deny":
            try:
                for ace2 in acl_list[count + 1 :]:
                    # Skip remarks
                    if ace1["action"] == "remark" or ace2["action"] == "remark":
                        continue

                    if (ace2["action"] == "permit") and (
                        ace1["protocol"] == ace2["protocol"]
                        or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                    ):
                        if (
                            ace2["source_network_obj"].subnet_of(
                                ace1["source_network_obj"]
                            )
                            or ace1["source_network"] == "any"
                        ):
                            if (
                                ace2["destination_network_obj"].subnet_of(
                                    ace1["destination_network_obj"]
                                )
                                or ace1["destination_network"] == "any"
                            ):
                                (
                                    src_port_match,
                                    dst_port_match,
                                ) = check_source_destination_ports_match(ace1, ace2)

                                if src_port_match and dst_port_match:
                                    for ace3 in acl_list2:
                                        if ace3["line_num"] == ace2["line_num"]:
                                            acl_list2.remove(ace3)
                                            break
            except IndexError:
                pass

    acl_list = acl_list2.copy()
    # Check permit that overlaps subsequent deny
    for count, ace1 in enumerate(acl_list):
        if ace1["action"] == "permit":
            try:
                for ace2 in acl_list[count + 1 :]:
                    # Skip remarks
                    if ace1["action"] == "remark" or ace2["action"] == "remark":
                        continue

                    if (ace2["action"] == "deny") and (
                        ace1["protocol"] == ace2["protocol"]
                        or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                    ):
                        if (
                            ace2["source_network_obj"].subnet_of(
                                ace1["source_network_obj"]
                            )
                            or ace1["source_network"] == "any"
                        ):
                            if (
                                ace2["destination_network_obj"].subnet_of(
                                    ace1["destination_network_obj"]
                                )
                                or ace1["destination_network"] == "any"
                            ):
                                (
                                    src_port_match,
                                    dst_port_match,
                                ) = check_source_destination_ports_match(ace1, ace2)

                                if src_port_match and dst_port_match:
                                    for ace3 in acl_list2:
                                        if ace3["line_num"] == ace2["line_num"]:
                                            acl_list2.remove(ace3)
                                            break
            except IndexError:
                pass

    return acl_list2


def check_overlapping_networks(acl_list):
    """
    Iterate through acl_list top down & bottom up, to remove ACEs with networks that are subnets of other entries.

    Parameters:
    acl_list (list of dict) - list of ACE dictionaries

    Returns:
    acl_list2 (list of dict) - remediated list of ACE dictionaries
    """
    acl_list2 = acl_list.copy()
    for count, ace1 in enumerate(acl_list):
        try:
            for ace2 in acl_list[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (
                        ace2["source_network_obj"].subnet_of(ace1["source_network_obj"])
                        or ace1["source_network"] == "any"
                    ):
                        if (
                            ace2["destination_network_obj"].subnet_of(
                                ace1["destination_network_obj"]
                            )
                            or ace1["destination_network"] == "any"
                        ):
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    acl_list = acl_list2.copy()
    for count, ace1 in enumerate(reversed(acl_list)):
        try:
            for ace2 in list(reversed(acl_list))[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (
                        ace2["source_network_obj"].subnet_of(ace1["source_network_obj"])
                        or ace1["source_network"] == "any"
                    ):
                        if (
                            ace2["destination_network_obj"].subnet_of(
                                ace1["destination_network_obj"]
                            )
                            or ace1["destination_network"] == "any"
                        ):
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    return acl_list2


def check_adjacent_networks(acl_list):
    """
    Iterate through acl_list top down & bottom up to merge adjacent networks.

    Parameters:
    acl_list (list of dict) - list of ACE dictionaries

    Returns:
    acl_list2 (list of dict) - remediated list of ACE dictionaries
    """
    acl_list2 = acl_list.copy()
    # Check source networks
    for count, ace1 in enumerate(acl_list):
        try:
            for ace2 in acl_list[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (ace1["destination_network"] == ace2["destination_network"]) or (
                        ace1["destination_network"] == "any"
                    ):
                        merged_network = list(
                            ipaddress.collapse_addresses(
                                [ace1["source_network_obj"], ace2["source_network_obj"]]
                            )
                        )
                        # ipaddress.collapse_addresses will return a single IPv4Network if passed adjacent networks
                        if len(merged_network) == 1:
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                # Replace with merged network
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace1["line_num"]:
                                        ace1["source_network"] = merged_network[
                                            0
                                        ].with_prefixlen
                                        ace1["source_network_obj"] = merged_network[0]
                                        break
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    acl_list = acl_list2.copy()
    for count, ace1 in enumerate(reversed(acl_list)):
        try:
            for ace2 in list(reversed(acl_list))[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (ace1["destination_network"] == ace2["destination_network"]) or (
                        ace1["destination_network"] == "any"
                    ):
                        merged_network = list(
                            ipaddress.collapse_addresses(
                                [ace1["source_network_obj"], ace2["source_network_obj"]]
                            )
                        )
                        # ipaddress.collapse_addresses will return a single IPv4Network if passed adjacent networks
                        if len(merged_network) == 1:
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                # Replace with merged network
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace1["line_num"]:
                                        ace1["source_network"] = merged_network[
                                            0
                                        ].with_prefixlen
                                        ace1["source_network_obj"] = merged_network[0]
                                        break
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    acl_list = acl_list2.copy()
    # Check destination networks
    for count, ace1 in enumerate(acl_list):
        try:
            for ace2 in acl_list[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (ace1["source_network"] == ace2["source_network"]) or (
                        ace1["source_network"] == "any"
                    ):
                        merged_network = list(
                            ipaddress.collapse_addresses(
                                [
                                    ace1["destination_network_obj"],
                                    ace2["destination_network_obj"],
                                ]
                            )
                        )
                        # ipaddress.collapse_addresses will return a single IPv4Network if passed adjacent networks
                        if len(merged_network) == 1:
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                # Replace with merged network
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace1["line_num"]:
                                        ace1["destination_network"] = merged_network[
                                            0
                                        ].with_prefixlen
                                        ace1[
                                            "destination_network_obj"
                                        ] = merged_network[0]
                                        break
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    acl_list = acl_list2.copy()
    for count, ace1 in enumerate(reversed(acl_list)):
        try:
            for ace2 in list(reversed(acl_list))[count + 1 :]:
                # Skip remarks
                if ace1["action"] == "remark" or ace2["action"] == "remark":
                    continue

                if (ace1["action"] == ace2["action"]) and (
                    ace1["protocol"] == ace2["protocol"]
                    or (ace1["protocol"] == "ip" or ace1["protocol"] == "ipv4")
                ):
                    if (ace1["source_network"] == ace2["source_network"]) or (
                        ace1["source_network"] == "any"
                    ):
                        merged_network = list(
                            ipaddress.collapse_addresses(
                                [
                                    ace1["destination_network_obj"],
                                    ace2["destination_network_obj"],
                                ]
                            )
                        )
                        # ipaddress.collapse_addresses will return a single IPv4Network if passed adjacent networks
                        if len(merged_network) == 1:
                            (
                                src_port_match,
                                dst_port_match,
                            ) = check_source_destination_ports_match(ace1, ace2)

                            if src_port_match and dst_port_match:
                                # Replace with merged network
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace1["line_num"]:
                                        ace1["destination_network"] = merged_network[
                                            0
                                        ].with_prefixlen
                                        ace1[
                                            "destination_network_obj"
                                        ] = merged_network[0]
                                        break
                                for ace3 in acl_list2:
                                    if ace3["line_num"] == ace2["line_num"]:
                                        acl_list2.remove(ace3)
                                        break
        except IndexError:
            pass

    return acl_list2


def display_ACL(acl_list, notation):
    """
    Print readable form of list of ACE dictionaries.

    Parameters:
    acl_list (list of dict) - list of ACE dictionaries
    notation (str) - ACL uses prefix, subnet or wildcard notation
    """
    for ace in acl_list:
        # Handle remarks
        if ace["action"] == "remark":
            parsed_ace = f"{ace['optional_action']}"
        else:
            # Generate correct output for different network notations
            # Subnet masks are first in the lookup dictionary, so use first match
            if notation == "subnet":
                if ace["source_network"] == "any":
                    source_network = ace["source_network"]
                else:
                    subnet_mask = ace["source_network"][
                        ace["source_network"].find("/") + 1 :
                    ]
                    for key, value in SUBNET_MASKS.items():
                        if subnet_mask == value:
                            source_network = ace["source_network"][
                                : ace["source_network"].find("/")
                            ]
                            source_network += f" {key}"
                            break
                if ace["destination_network"] == "any":
                    destination_network = ace["destination_network"]
                else:
                    subnet_mask = ace["destination_network"][
                        ace["destination_network"].find("/") + 1 :
                    ]
                    for key, value in SUBNET_MASKS.items():
                        if subnet_mask == value:
                            destination_network = ace["destination_network"][
                                : ace["destination_network"].find("/")
                            ]
                            destination_network += f" {key}"
                            break
            # Wildcard masks are second in the lookup dictionary, so use last match
            elif notation == "wildcard":
                if ace["source_network"] == "any":
                    source_network = ace["source_network"]
                else:
                    subnet_mask = ace["source_network"][
                        ace["source_network"].find("/") + 1 :
                    ]
                    for key, value in SUBNET_MASKS.items():
                        if subnet_mask == value:
                            source_network = ace["source_network"][
                                : ace["source_network"].find("/")
                            ]
                            source_network += f" {key}"
                            continue
                if ace["destination_network"] == "any":
                    destination_network = ace["destination_network"]
                else:
                    subnet_mask = ace["destination_network"][
                        ace["destination_network"].find("/") + 1 :
                    ]
                    for key, value in SUBNET_MASKS.items():
                        if subnet_mask == value:
                            destination_network = ace["destination_network"][
                                : ace["destination_network"].find("/")
                            ]
                            destination_network += f" {key}"
                            continue
            # Default to prefix notation, no special handling
            else:
                source_network = ace["source_network"]
                destination_network = ace["destination_network"]

            parsed_ace = (
                f"{ace['action']} "
                f"{ace['protocol']} "
                f"{source_network} "
                f"{ace['source_operator']} "
                f"{' '.join(str(x) for x in ace['source_ports']) if ace['source_ports'] else ''} "
                f"{ace['source_modifier']} "
                f"{destination_network} "
                f"{ace['destination_operator']} "
                f"{' '.join(str(x) for x in ace['destination_ports']) if ace['destination_ports'] else ''} "
                f"{ace['destination_modifier']} "
                f"{ace['optional_action']} "
            )
        print(re.sub(r" +", " ", parsed_ace))


def main():
    """
    Ties the whole process together.
    """
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} [filename] [verbose]")
        print(
            "\nVerbose keyword enables optional output of the intermediate ACL de-crufting stages."
        )
        sys.exit(1)

    if len(sys.argv) == 3:
        if sys.argv[2].lower() == "verbose":
            verbose_mode = True
    else:
        verbose_mode = False

    try:
        filepath = Path(sys.argv[1])
        with open(filepath) as f:
            acl_string = f.read()
    except FileNotFoundError:
        print(f"Unable to open {sys.argv[1]}")
        sys.exit(1)

    acl_list, notation = parse_acl(acl_string)

    # Sanity checks
    for ace in acl_list:
        assert isinstance(ace["line_num"], str)
        assert ace["action"] in ("permit", "deny", "remark")
        if ace["action"] == "remark":
            assert isinstance(ace["optional_action"], str)
        else:
            assert ace["protocol"] in PROTOCOL_NAMES
            assert re.search("\d+\.\d+\.\d+\.\d+\/\d+|any", ace["source_network"])
            assert isinstance(ace["source_network_obj"], ipaddress.IPv4Network)
            if ace["source_operator"] == "eq" or ace["source_operator"] == "neq":
                assert ace["source_ports"][0] >= 0 and ace["source_ports"][0] <= 65535
            elif ace["source_operator"] == "lt" or ace["source_operator"] == "gt":
                assert ace["source_ports"][0] >= 0 and ace["source_ports"][0] <= 65535
            elif ace["source_operator"] == "range":
                assert (
                    ace["source_ports"][0] >= 0 and ace["source_ports"][0] <= 65535
                ) and (ace["source_ports"][1] >= 0 and ace["source_ports"][1] <= 65535)
            assert isinstance(ace["source_modifier"], str)
            assert re.search("\d+\.\d+\.\d+\.\d+\/\d+|any", ace["destination_network"])
            assert isinstance(ace["destination_network_obj"], ipaddress.IPv4Network)
            if (
                ace["destination_operator"] == "eq"
                or ace["destination_operator"] == "neq"
            ):
                assert (
                    ace["destination_ports"][0] >= 0
                    and ace["destination_ports"][0] <= 65535
                )
            elif (
                ace["destination_operator"] == "lt"
                or ace["destination_operator"] == "gt"
            ):
                assert (
                    ace["destination_ports"][0] >= 0
                    and ace["destination_ports"][0] <= 65535
                )
            elif ace["destination_operator"] == "range":
                assert (
                    ace["destination_ports"][0] >= 0
                    and ace["destination_ports"][0] <= 65535
                ) and (
                    ace["destination_ports"][1] >= 0
                    and ace["destination_ports"][1] <= 65535
                )
            assert isinstance(ace["destination_modifier"], str)
            assert isinstance(ace["optional_action"], str)

    if verbose_mode:
        print("\nOriginal ACL:")
        display_ACL(acl_list, notation)

    # Note that IPv4Network.subnet_of() considers identical networks as a subnet, so need to skip comparing to self
    acl_list2 = check_overlapping_deny_permit(acl_list)
    if verbose_mode:
        # Display ACL with denied ACEs removed
        print("\nRemoved Deny/Permit Overlapping Subsequent Permit/Deny ACL:")
        display_ACL(acl_list2, notation)

    acl_list = acl_list2.copy()
    acl_list2 = check_overlapping_networks(acl_list)
    if verbose_mode:
        # Display ACL with overlapping ACEs removed
        print("\nRemoved Overlapping Networks ACL:")
        display_ACL(acl_list2, notation)

    acl_list = acl_list2.copy()
    acl_list2 = check_adjacent_networks(acl_list)
    if verbose_mode:
        # Display ACL with adjacent networks merged
        print("\nMerged Adjacent Networks ACL:")
        display_ACL(acl_list2, notation)

    # Display decrufted ACL
    print("\nDecrufted ACL:")
    display_ACL(acl_list2, notation)


if __name__ == "__main__":
    main()
