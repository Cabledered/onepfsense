# PfSense app for OpenNebula

## Overview

This repo explain how to use the unofficial and private OpenNebula appliance for [pfSense](https://www.pfsense.org "Go to pfSense homepage"), the most trusted open source Unified Threat Management (UTM) in the world.

## Appliance customization keys

The appliance allow the automated standalone and HA deployment for pfSense, as a VRouter in OpenNebula. Using our custome contextualization script in bash, there are some actions through the contextualization, that may help the user to modify the pfsense fom the OpenNebula Sunstone. These are the main features:

- Automated deployment of a pfSense 2.7.2 standalone VRouter.
- Automated deployment of a pfSense 2.7.2 HA VRouter.
- The appliance include the following installed packages:
  - Backup: `0.6`.
  - Cron: `0.3.8_3`.
  - haproxy: `0.63_2`.
  - iperf: `3.0.3`.
  - openvpn-client-export: `1.9.2`.
  - Shellcmd: `1.0.5_3`.
  - sudo: `0.3_8`.
  - suricata: `7.0.6`.
  - WireGuard: `0.2.1`.
- Hardened OpenVPN server.
- Access to the WebGUI through: https://<pfsense_wan_ip>:9999.
- Access to SSH through: `2222/tcp`.
- Preconfigured set of rules for the firewall interfaces with NAT Outbound.
- Contextualization script logs can by checked on: `/var/log/onecontext.log`.

