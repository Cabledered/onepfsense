# PfSense app for OpenNebula

This is a private appliance available only on private Marketplaces.

## 1.1. Overview

This repo explain how to use the unofficial and private OpenNebula appliance for [pfSense](https://www.pfsense.org "Go to pfSense homepage"), the most trusted open source Unified Threat Management (UTM) in the world. The appliance is inttended to be used for customers where their infrastructure are in the cloud. Beside of the FW security riles, the pfSense will have access to the public network and it will prepared with services for Load Balance and VPN access to the customer's cloud infrastructure, on the pfSense LAN network.

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

# 3. Creating your LAN private networks

Create the private network for the pfSense LAN interface:

![imagen](https://github.com/user-attachments/assets/07eccf1f-578a-4b1d-8310-05c793b6e375)

Add an address range:

![imagen](https://github.com/user-attachments/assets/088dd2e2-5684-4517-b1b4-ff73f233bbce)

Fill the required info:

![imagen](https://github.com/user-attachments/assets/c99f3300-4ba2-445e-a12b-83f0a8f4172e)

Instantiate the new private network:

![imagen](https://github.com/user-attachments/assets/177865d9-da02-48a9-bdfe-34324f49f4ed)

Notification without errors about the previous action, should appear in the lower right corner.

Modify the created private network:

![imagen](https://github.com/user-attachments/assets/ab1b2d37-5850-4668-9fe6-4c7067e80f90)

Fill the required info for the network contextualization:

![imagen](https://github.com/user-attachments/assets/0d240cf3-bbfc-43a4-85d4-b24c6fde7dc4)

> **NOTE**: Make always the pfSense LAN IP as the Gateway of the LAN Virtual Network.

It is assumed that the cloud provider has already allocated a pool of public Ips for the customer. This Virtual Network should have exist before continue.

# 4. Deploying a standalone pfSense VRouter

Required info for the deployment:

- WAN IP: `144.168.40.133`
- LAN IP: `192.168.0.1`
- HOSTNAME: `pfsense`
- DOMAIN: `local.kz`
- PASSWORD for user `admin`: `YourStrongPass`



![imagen](https://github.com/user-attachments/assets/7c543ed9-996a-4058-a30d-1c7cf527a297)

