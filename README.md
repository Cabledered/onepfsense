# PfSense app for OpenNebula

This is a private appliance available only on private Marketplaces.

## 1.1. Overview

This repo explain how to use the unofficial and private OpenNebula appliance for [pfSense](https://www.pfsense.org "Go to pfSense homepage"), the most trusted open source Unified Threat Management (UTM) in the world.

## 1.2. Appliance customization keys

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

# 2. Downloading the appliance from the Marketplace

The appliance is only available in private marketplaces, deployed by the authors of the appliance.

![imagen](https://github.com/user-attachments/assets/0f2c1cd2-ba29-49a1-b5ac-896bc7d3b9ba)

More information related with the image in the picture below:

![imagen](https://github.com/user-attachments/assets/5d55b55a-8301-4bd6-91c7-25753d919489)

Locate the appliance in the marketplace:

![imagen](https://github.com/user-attachments/assets/062f485f-e424-4594-a7bb-3a76db6a9aae)

Download it to one of the available datastores:

![imagen](https://github.com/user-attachments/assets/42eec91b-1005-4167-82d0-1f73a6c8e7c9)

Notification without errors about the previous action, should appear in the lower right corner.

Wait for the image to be in READY for use:

![imagen](https://github.com/user-attachments/assets/90019705-d9a4-414c-ae2a-9c17a57b62e9)


