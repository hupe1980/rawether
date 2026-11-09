# Research: EtherType names

Values were checked against Linux `include/uapi/linux/if_ether.h` (2026-11-09) and the IEEE
Registration Authority EtherType list. GOOSE (0x88B8), GSE management (0x88B9) and Sampled
Values (0x88BA) are IEEE assignments for IEC 61850-8-1 and IEC 61850-9-2 that Linux does not
list.

| Name | Value | Source |
|---|---|---|
| IPV4 | 0x0800 | `ETH_P_IP` |
| ARP | 0x0806 | `ETH_P_ARP` |
| AVTP | 0x22F0 | `ETH_P_TSN` (IEEE 1722) |
| VLAN | 0x8100 | `ETH_P_8021Q` |
| IPV6 | 0x86DD | `ETH_P_IPV6` |
| EAPOL | 0x888E | `ETH_P_PAE` (IEEE 802.1X) |
| PROFINET | 0x8892 | `ETH_P_PROFINET` |
| ETHERCAT | 0x88A4 | `ETH_P_ETHERCAT` |
| QINQ | 0x88A8 | `ETH_P_8021AD` |
| LOCAL_EXPERIMENTAL_1 | 0x88B5 | `ETH_P_802_EX1` |
| LOCAL_EXPERIMENTAL_2 | 0x88B6 | IEEE 802 Local Experimental 2 |
| GOOSE | 0x88B8 | IEC 61850-8-1 |
| GSE | 0x88B9 | IEC 61850-8-1 GSE management |
| SAMPLED_VALUES | 0x88BA | IEC 61850-9-2 |
| LLDP | 0x88CC | `ETH_P_LLDP` |
| MRP | 0x88E3 | `ETH_P_MRP` (IEC 62439-2) |
| MACSEC | 0x88E5 | `ETH_P_MACSEC` |
| PTP | 0x88F7 | `ETH_P_1588` |
| PRP | 0x88FB | `ETH_P_PRP` (IEC 62439-3 PRP/HSRv0 supervision) |
| CFM | 0x8902 | `ETH_P_CFM` (IEEE 802.1ag) |
| HSR | 0x892F | `ETH_P_HSR` (IEC 62439-3) |

- **Decision:** 0x9100 (pre-standard Q-in-Q) is left unnamed, because it is not registered.
- **Decision:** values below 0x0600 are 802.3 lengths; they get no name and print as a number.
