# IEC 61850-8-1 GOOSE Parser

IEC 61850 GOOSE (Generic Object Oriented System Event) is a communication protocol for industrial control systems.
It is based on IEEE 802.1Q VLAN or ethernet frames.

## Overview

This IEC 61850 goose parser is a Zeek plugin (written in spicy) for parsing and logging fields used by the Goose protocol.

This parser produces a the log file `goose.log`, defined in [scripts/main.zeek](scripts/main.zeek).

## Installation

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
cmake . && make install
zeek -NN | grep ANALYZER_SPICY_GOOSE
```

If this package is installed from `zkg` it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_SPICY_GOOSE` under the list of `Zeek::Spicy` analyzers.

If you have `zkg` configured to load packages (see `@load packages` in the [`zkg` Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Logging Capabilities

### Goose Log (goose.log)

This parser evaluates ethernet or VLAN frames with an ethertype of `0x88b8`.

#### Fields Captured

The following data fields (specified in IEC 61850-8-1 Annex A.3) are written to `goose.log`.

| Field | Type | Description | Reference |
|-------|------|-------------|-----------|
| ts | time | Zeek observation time | - |
| src_mac | string | Ethernet source MAC | IEEE 802.3 |
| dst_mac | string | Ethernet destination MAC | IEEE 802.3 |
| eth_type | string | GOOSE EtherType, emitted as `0x88b8` | IEC 61850-8-1 |
| appid | string | Application ID, emitted as `0x`-prefixed hexadecimal | IEC 61850-8-1 Annex C.2 PDU fields |
| length | int | Packet length | IEC 61850-8-1 Annex C.2 PDU fields |
| gocb_ref | string | GOOSE Control Block Reference | IEC 61850-7-2 Chapter 18.2.1.2 |
| time_allowed_to_live | int | Time allowed for the GOOSE packet to live within the network | IEC 61850-8-1 Chapter 18.1.2.5.1 |
| dataset | string | Data set transmitted within this packet | IEC 61850-8-1 Chapter 18.1.2.1 |
| go_id | string | Optional GOOSE identifier | IEC 61850-7-2 Chapter 18.2.3.1 |
| timestamp | time | GOOSE internal `T` timestamp, derived from seconds and fractionOfSecond | IEC 61850-7-2 Chapter 18.2.3.1 |
| timestamp_quality | string | Final timeQuality byte from the GOOSE internal `T` value, emitted as `0x`-prefixed hexadecimal | IEC 61850-7-2 Chapter 18.2.3.1 |
| st_num | int | GOOSE state number | IEC 61850-7-2 Chapter 18.2.3.1 |
| sq_num | int | GOOSE sequence number | IEC 61850-7-2 Chapter 18.2.3.1 |
| simulation | bool | Indicates whether the packet is from simulation | IEC 61850-7-2 Chapter 18.2.3.1 |
| conf_rev | int | GOOSE configuration revision | IEC 61850-7-2 Chapter 18.2.3.1 |
| nds_com | bool | Needs commissioning flag | IEC 61850-7-2 Chapter 18.2.3.1 |
| num_dat_set_entries | int | Number of entries in the data set | IEC 61850-8-1 Chapter 18.1.2.5.2 |

## Others

The software was developed on behalf of the [BSI](https://www.bsi.bund.de) \(Federal Office for Information Security\) by the electrical energy systems research group at Fraunhofer [Institute Advanced Systems Technology (AST)](https://www.iosb-ast.fraunhofer.de/en.html), a branch of Fraunhofer [ISOB](https://www.iosb.fraunhofer.de/en.html).

## Licenses

Copyright (c) 2023-2026 by DINA-Community. [See License](/LICENSE)

### Third party licenses

This projects uses code from [spicy-ldap](https://github.com/zeek/spicy-ldap/blob/main/analyzer/asn1.spicy) under the license provided in [asn1.spicy](analyzer/asn1.spicy) for all provided parsers.
