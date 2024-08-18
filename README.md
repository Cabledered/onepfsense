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

Put the name of the VRouter:

![imagen](https://github.com/user-attachments/assets/f6547174-c079-4da2-8438-ea1f0d965c98)

Is not mandatory to force the IP, but it will be done in this example:

![imagen](https://github.com/user-attachments/assets/7043cdbd-a2a1-436e-827e-dce630bfef2b)

Add the LAN interface. It is adviseable t force the IP in this case, to make sure the pfSense LAN IP is the Gateway of the LAN Virtual Network:

![imagen](https://github.com/user-attachments/assets/afef064b-840c-4e82-8b44-25f6763d85a0)

Fill the remaining info for the instantiation of the VRouter:

![imagen](https://github.com/user-attachments/assets/fd4d823b-6fac-448a-98bc-07a4a602dd07)

When you are done here, you are ready to complete the instantiation of the VRouter:

![imagen](https://github.com/user-attachments/assets/6ce52358-7fdc-4267-8a3f-b53b9e5cf065)

Check the created VRouter:

![imagen](https://github.com/user-attachments/assets/863dd199-882c-477b-8965-9da87c14ec62)

It would looks like follow:

![imagen](https://github.com/user-attachments/assets/a857a7d2-bdd4-4edf-b42b-d0b3b4acf09d)

In the VMs tab, of the given VRouter, it will appear the associated VM for this standalone pfSense VRouter:

![imagen](https://github.com/user-attachments/assets/f10bc310-6e7a-4b0b-bd80-f52fdf98a043)

Wait from 2 to 4 minutes, and the appliance will be ready. It will reboot and after bootup again, the pfSense will be ready for use, already installed and running with the provided contextualization parameters:

![imagen](https://github.com/user-attachments/assets/9a96fadb-27ff-4e59-923b-974b5ddf3471)

Open your browser and access to the VRouter public IP:

![imagen](https://github.com/user-attachments/assets/ca0f2e06-a4ec-467e-a3c5-cd20f728b745)

The script is not perfect, so any incoherence with the contextualization, edit it manually from the pfSense WebGUI:

![imagen](https://github.com/user-attachments/assets/321ba2c7-a1cc-4fdc-abde-1edc38334a65)

# 5. Deploying an HA pfSense VRouter

Required info for the deployment:

- WAN VIP: `144.168.40.133`
- Primary pfSense WAN IP: `144.168.40.131`
- Secondary pfSense WAN IP: `144.168.40.132`
- LAN VIP: `192.168.0.1`
- Primary pfSense LAN IP: `192.168.0.2`
- Secondary pfSense LAN IP: `192.168.0.3`
- HOSTNAME: `pfsense`
- DOMAIN: `local.kz`
- PASSWORD for user `admin`: `YourStrongPass`

The proceedure is the same as the standalone deployment, except for the number of instances to be deployed and that in this case it is required to specify the VRouter Floating IP (the VIP).

For public network:

![imagen](https://github.com/user-attachments/assets/7708122c-85a5-41ae-9d70-72f3cd731fa3)

For LAN private network:

![imagen](https://github.com/user-attachments/assets/e6dc3772-1f58-45dc-82b3-fe412407bf50)

Number of instances:

![imagen](https://github.com/user-attachments/assets/845f032c-062d-4c5a-8f52-67477f6a6894)

Primary pfSense instance of the VRouter:

![WhatsApp Image 2024-08-17 at 4 46 38 PM](https://github.com/user-attachments/assets/8090d3f1-ce12-45d5-998b-fea0021c4e2d)

Secondary pfSense instance of the VRouter:

![WhatsApp Image 2024-08-17 at 4 47 00 PM](https://github.com/user-attachments/assets/b9d6d440-e5af-4a04-af27-974e0afb711e)

Some notes on about this deployment:

- The two instances of the VRouter will automatically be configured and it could take around `10min` to finish the auto-configuration.
- In case the domain name be the same as the hostname, you can edit it from the contextualization variables of the VM (`SET_HOSTNAME`), same for the hostanme variable (`HOSTNAME`).
- If the primary pfSense WebGUI is still not available from the public network, after `10min`. try reboot the VM instance.
- Once you be able to access to each pfSense WebGUI. Update the WAN CARP IP and the LAN CARP IP, with the real values for WAN floating IP and LAN floating IP (contextualization script is not ready to configure this automatically).
- The local network of the OpenVPN server might be updated manually from the pfSense WebGUI.
- Find more information related with pfSense HA setup [here](https://docs.netgate.com/pfsense/en/latest/highavailability/index.html "High Availability").


