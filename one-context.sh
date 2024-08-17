#!/usr/local/bin/bash

#----------------------------------------------------------------------------------------------+
# Author: Frank Luis Morales, Franco Diaz, Ignacio Pascual                                     |
# Script version: 2.7.2-1                                                                      |
# Brief summary of the script: The script will allow the contextualization of the pfsense,     |
#                              which is running under FreeBSD 12.3. It offer the following     |
#                              features:                                                       |
#                              - Change the admin password.                                    |
#                              - Change the WAN and LAN IP.                                    |
#                              - Change the server address of the OpenVPN server when there is |
#                              a change on the WAN IP.                                         |
#                              - Change the hostname.                                          |
#                              - Change the domain.                                            |
#                              - Change the WANGW.                                             |
#----------------------------------------------------------------------------------------------+

########
# INDEX
########

# 1. GLOBAL VARIABLES
# 2. CUSTOM FUNCTIONS
# 3. SCRIPT'S BODY
#  3.1. Is this pfsense for HA?
#  3.2. Update "local_one_env" from "config.xml"
#  3.3. Compare "one_env" with "local_one_env"
#     3.3.1. Set vnet0~eth0 (WAN IP)/mask/gateway/openvpn-server
#     3.3.2. Set vnet1~eth1 (LAN IP)/mask/openvpn-server
#     3.3.3. Set Hostname
#     3.3.4. Change domain
#     3.3.5. Change root (admin) password
#     3.3.6. Pfsense High Availability
#     3.3.7. Reload pfsense configuration if necessary
#  3.4. Firewall rules for PFSYNC

######################
# 1. GLOBAL VARIABLES
######################

# Config files
config="/cf/conf/config.xml"
config_standalone="/root/config_standalone.xml"
config_primary="/root/config_primary.xml"
config_secondary="/root/config_secondary.xml"
one_env="/var/run/one-context/one_env"
if [ ! -f /root/onecontext/one_env ]; then
  cp /root/onecontext/one_env.orig /root/onecontext/one_env
  chmod 400 /root/onecontext/one_env
fi
local_one_env="/root/onecontext/one_env"
if [ ! -f /var/log/onecontext.log ]; then
  touch /var/log/onecontext.log
fi
logfile="/var/log/onecontext.log"

# Reset flags
reset_config="0"
reset_config_2="0"
standalone="0"
primary_node="0"
secondary_node="0"

# Colours vars
RED='\033[01;31m'
GREEN='\033[01;32m'
YELLOW='\033[01;33m'
NC='\033[0m'

######################
# 2. CUSTOM FUNCTIONS
######################

check_log_last_line(){
  # Check last line from logfile
  log_last_line=`cat $logfile | tail -n 1`
  if [[ "$log_last_line" =~ "Starting Script" ]]; then
    ## Nothing more was printed and this line must be removed from the logfile
    sed -i '' '$d' $logfile
  fi
}

check_nics_condition() {
  # Check the VM hostname
  new_hostname=`grep -w "SET_HOSTNAME" $one_env | cut -d'"' -f2`

  # Gather the current number of NICs on the pfsense
  nics=$(ifconfig | egrep "vtnet[0-2]|re[0-2]" | grep flags | wc -l | awk '{print $1}')

  # Check NICs condition
  eth0_vrouter_new_ip=`grep -w "ETH0_VROUTER_IP" $one_env | cut -d \" -f2`
  if [[ $eth0_vrouter_new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ## The "one_env" includes the context var "ETH0_VROUTER_IP"
    ## So, this pfsense was instantiated for HA purposes
    min_nics=3
    if [ $nics -lt $min_nics ]; then
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: The pfsense has $(echo -e ${RED}$nics${NC}) and the appliance needs a minimum of ${GREEN}$min_nics${NC} NICs" >> "${logfile}"
      echo "" >> "${logfile}"

      ## Exiting from the script
      $(check_log_last_line)
      exit 0
    fi
  else
    ## The "one_env" does not include the context var "ETH0_VROUTER_IP"
    ## So, this pfsense was instantiated for single node purposes
    min_nics=2
      if [ $nics -lt $min_nics ]; then
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: The pfsense has $(echo -e ${RED}$nics${NC}) and the appliance needs a minimum of ${GREEN}$min_nics${NC} NICs" >> "${logfile}"
        echo "" >> "${logfile}"

        ## Exiting from the script
        $(check_log_last_line)
        exit 0
      fi
  fi
}

apply_config_primary(){
  cp $config_primary $config
  rm /tmp/config.cache
  mv $config_standalone ${config_standalone}.bak
  mv $config_primary ${config_primary}.bak
  mv $config_secondary ${config_secondary}.bak
}

apply_config_secondary(){
  cp $config_secondary $config
  rm /tmp/config.cache
  mv $config_standalone ${config_standalone}.bak
  mv $config_primary ${config_primary}.bak
  mv $config_secondary ${config_secondary}.bak
}

apply_config_standalone(){
  cp $config_standalone $config
  rm /tmp/config.cache
  mv $config_standalone ${config_standalone}.bak
  mv $config_primary ${config_primary}.bak
  mv $config_secondary ${config_secondary}.bak
}

force_change_password(){
  # Gather new_root_pass
  new_root_pass=`grep PASSWORD $one_env | grep -v ROOT | cut -d'"' -f2`

  # Update the "local_one_env" with the admin password defined from instantiation
  sed -i -r "s#PASSWORD=.*#PASSWORD=\"$new_root_pass\"#" $local_one_env

  # Applying the password provided from the instantiation
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating root_pass to ${GREEN}\"${new_root_pass:0:1}****${new_root_pass: -1}\"${NC}" >> "${logfile}"
  printf "admin\n${new_root_pass}\n${new_root_pass}\n" | pfSsh.php playback changepassword
  sleep 2

  # Enable the flag for root_pass changed
  reset_config_2="1"
}

get_ethx_name(){
  # Get the name of ETH0
  eth0_name=`ifconfig -a | egrep "vtnet0|re0" | awk -F ":" '{print $1}' | head -n 1`
  # Get the name of ETH1
  eth1_name=`ifconfig -a | egrep "vtnet1|re1" | awk -F ":" '{print $1}' | head -n 1`
  # Get the name of ETH2
  eth2_name=`ifconfig -a | egrep "vtnet2|re2" | awk -F ":" '{print $1}' | head -n 1`
}

get_ethx_ip() {
  # Get the old ethx_ip from the pfsense config file
  if [ "$ETHX_IP" == "ETH0_IP" ]; then
      # ETHX_IP is ETH0_IP
      ethx_old_ip=`grep -nw "ipaddr" $config | sed -n 1p | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
  fi

  if [ "$ETHX_IP" == "ETH1_IP" ]; then
      # ETHX_IP is ETH1_IP
      ethx_old_ip=`grep -nw "ipaddr" $config | sed -n 2p | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
  fi

  if [ "$ETHX_IP" == "ETH2_IP" ]; then
      # ETHX_IP is ETH2_IP
      ethx_old_ip=`grep -nw "ipaddr" $config | sed -n 3p | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
  fi

  # Get the new ethx_ip from the "one_env" file
  ethx_new_ip=`cat $one_env | grep -w $ETHX_IP | cut -d \" -f2`
}

change_ovpn_client_wan_ip() {
  # Changing openvpn-client configuration
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating server_addr of openvpn-client from ${YELLOW}\"${eth0_old_ip}\"${NC} to ${GREEN}\"${eth0_new_ip}\"${NC}" >> "${logfile}"
  sed -i -r "s#<server_addr>.*</server_addr>#<server_addr>${eth0_new_ip}</server_addr>#" $config
}

restart-ovpn-server() {
  echo -e "${DATE}: Restarting openvpn-server \"server1\"" >> "${logfile}"
  /usr/local/sbin/pfSsh.php playback svc restart openvpn server 1
}

restart-ovpn-client() {
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Restarting openvpn-client \"client2\"" >> "${logfile}"
  /usr/local/sbin/pfSsh.php playback svc restart openvpn client 2
}

get_eth0_gw(){
  # Get the old eth0_gw from the "local_one_env" file
  eth0_old_gw_linenumber=`grep -oEn '<gateway>*[0-9]+' $config | head -n 1 | cut -d ":" -f1`
  eth0_old_gw=`grep ETH0_GATEWAY $local_one_env | sed -n 1p | cut -d \" -f2`
  # Get the new eth0_ip from the one_env
  eth0_new_gw=`grep ETH0_GATEWAY $one_env | sed -n 1p | cut -d \" -f2`
}

get_ethx_mask() {
  # Get the old ethx_mask from the pfsense config file
  if [ "$ETHX_MASK" == "ETH0_MASK" ]; then
    # ETHX_MASK is ETH0_MASK
    ethx_old_mask_cidr=`grep -En '<subnet>' $config | sed -n 1p | cut -d ">" -f2 | cut -d "<" -f1`
  fi

  if [ "$ETHX_MASK" == "ETH1_MASK" ]; then
    # ETHX_MASK is ETH1_MASK
    ethx_old_mask_cidr=`grep -En '<subnet>' $config | sed -n 2p | cut -d ">" -f2 | cut -d "<" -f1`
  fi

  if [ "$ETHX_MASK" == "ETH2_MASK" ]; then
    # ETHX_MASK is ETH0_MASK
    ethx_old_mask_cidr=`grep -En '<subnet>' $config | sed -n 3p | cut -d ">" -f2 | cut -d "<" -f1`
  fi

  # Get the new ethx_ip from the "one_env" file
  ethx_new_mask=`cat $one_env | grep -w $ETHX_MASK | cut -d \" -f2`
}

netmask_to_cidr() {
  # Return prefix for given netmask in arg1
  bits=0
  for octet in $(echo $1| sed 's/\./ /g'); do
    binbits=$(echo "obase=2; ibase=10; ${octet}"| bc | sed 's/0//g')
    let bits+=${#binbits}
  done
  echo "${bits}"
}

get_eth1_net(){
  # Gather old eth1_net from "local_one_env" file
  eth1_old_net=`grep -w "ETH1_NETWORK" $local_one_env | cut -d'"' -f2`
  # Gather new eth1_net from "one_env" file
  eth1_new_net=`grep -w "ETH1_NETWORK" $one_env | cut -d'"' -f2`
}

set_ovpn_server_local_network() {
  # Changing openvpn-server configuration
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the local_network of openvpn-server \"server1\" config from ${YELLOW}\"${eth1_old_net}/${eth1_old_mask_cidr}\"${NC} to ${GREEN}\"${eth1_new_net}/${eth1_new_mask_cidr}\"${NC}" >> "${logfile}"
  sed -i -r "s#<local_network>.*</local_network>#<local_network>${eth1_new_net}/${eth1_new_mask_cidr}</local_network>#" $config
}

get_ethx_vrouter_ip(){
  # Get the old ethx_vrouter_ip from the pfsense config file
  linenumber=${string::-1}
  ethx_vrouter_old_ip_linenumber=$(expr $linenumber + 3)
  ethx_vrouter_old_ip=`sed -n ${ethx_vrouter_old_ip_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
  # Get the new ethx_vrouter_ip from the "one_env" file
  ethx_vrouter_new_ip=`cat $one_env | grep -w "$ETHX_VROUTER_IP" | cut -d \" -f2`
}

get_wan_vip_uniqid(){
  # Get the old wan_vip_uniqid for WAN VIP CARP from the pfsense config file in the <openvpn-server> section
  string=`grep -nw "WAN VIP CARP" $config | awk '{print $1}'`
  linenumber=${string::-1}
  wan_vip_uniqid_linenumber=$(expr $linenumber - 1)
  # Get the new wan_vip_uniqid for WAN VIP CARP from the "one_env" file
  wan_vip_uniqid=`sed -n ${wan_vip_uniqid_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
}

set_ovpn_server_wan_vip(){
  # Change to the current ovpn_server_interface and eth0_vrouter_ip
  string=`grep -nw "<vpnid>1</vpnid>" $config | awk '{print $1}'`
  linenumber=${string::-1}
  ovpn_server_interface_linenumber=$(expr $linenumber + 5)
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the interface of openvpn-server \"server1\" config to ${GREEN}\"_vip${wan_vip_uniqid}\"${NC}" >> "${logfile}"
  sed -i -r "${ovpn_server_interface_linenumber}s#<interface>.*</interface>#<interface>_vip${wan_vip_uniqid}</interface>#" $config
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the IP address of the interface ${YELLOW}\"_vip${wan_vip_uniqid}\"${NC} (WAN VIP CARP) to ${GREEN}\"${eth0_vrouter_new_ip}\"${NC}" >> "${logfile}"
  sed -i -r "$(expr $ovpn_server_interface_linenumber + 1)s#<ipaddr>.*</ipaddr>#<ipaddr>${eth0_vrouter_new_ip}</ipaddr>#" $config
}

update_ovpn_client_config(){
  # Get the old vip_wan_id for WAN VIP CARP from the pfsense config file in the <openvpn-client> section,
  # of the first openvpn-client provided by the appliance
  string=`grep -nw "<openvpn-client>" $config | head -n 1 | awk '{print $1}'`
  linenumber=${string::-1}
  ovpn_client_interface_linenumber=$(expr $linenumber + 8)
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the interface of openvpn-client \"client2\" to ${GREEN}\"_vip${wan_vip_uniqid}\"${NC}" >> "${logfile}"
  sed -i -r "${ovpn_client_interface_linenumber}s#<interface>.*</interface>#<interface>_vip${wan_vip_uniqid}</interface>#" $config
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the IP address of interface ${YELLOW}\"_vip${wan_vip_uniqid}\"${NC} (WAN VIP CARP) to ${GREEN}\"${eth0_vrouter_new_ip}\"${NC}" >> "${logfile}"
  sed -i -r "$(expr $ovpn_client_interface_linenumber + 1)s#<ipaddr>.*</ipaddr>#<ipaddr>${eth0_vrouter_new_ip}</ipaddr>#" $config
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Updating the server addres of openvpn-client \"client2\" config to ${GREEN}\"${eth0_vrouter_new_ip}\"${NC}" >> "${logfile}"
  sed -i -r "$(expr $ovpn_client_interface_linenumber + 3 )s#<server_addr>.*</server_addr>#<server_addr>${eth0_vrouter_new_ip}</server_addr>#" $config
}

function set_variables {
export cidr_32=255.255.255.255
export cidr_31=255.255.255.254
export cidr_30=255.255.255.252
export cidr_29=255.255.255.248
export cidr_28=255.255.255.240
export cidr_27=255.255.255.224
export cidr_26=255.255.255.192
export cidr_25=255.255.255.128
export cidr_24=255.255.255.0
export cidr_23=255.255.254.0
export cidr_22=255.255.252.0
export cidr_21=255.255.248.0
export cidr_20=255.255.240.0
export cidr_19=255.255.224.0
export cidr_18=255.255.192.0
export cidr_17=255.255.128.0
export cidr_16=255.255.0.0
export cidr_15=255.254.0.0
export cidr_14=255.252.0.0
export cidr_13=255.248.0.0
export cidr_12=255.240.0.0
export cidr_11=255.224.0.0
export cidr_10=255.192.0.0
export cidr_9=255.128.0.0
export cidr_8=255.0.0.0
export cidr_7=254.0.0.0
export cidr_6=252.0.0.0
export cidr_5=248.0.0.0
export cidr_4=240.0.0.0
export cidr_3=224.0.0.0
export cidr_2=192.0.0.0
export cidr_1=128.0.0.0
}

## This variable is just an example to make it run the following function
export IP_CIDR="192.168.1.0/24"
# A function to detect CIDR like /32
function detect_cidr {
export IP=`echo $IP_CIDR | cut -d"/" -f1`
export CIDR=`echo $IP_CIDR | cut -d"/" -f2`
export CIDR_TEST=`echo $CIDR | grep "\."`
  if [[ "$CIDR_TEST" != "" ]]; then
    echo "CDIR is not valid"
    exit 1
  fi
  if [[ "$CIDR" -gt "32" ]] || [[ "$CIDR" -lt "1" ]] || [[ "$CIDR" == "" ]]; then
    echo "CIDR is not valid"
    exit 1
  fi
}

# Function to convert CIDR like /32 to 255.255.255.255
function print_subnet {
echo "echo $IP/\$cidr"_$CIDR | /usr/local/bin/bash
}

###################
# 3. SCRIPT'S BODY
###################

DATE=$(date +%Y-%m-%d-T%H:%M:%S)
echo -e "${DATE}: ${YELLOW}==========${NC} ${GREEN}Starting Script${NC} ${YELLOW}==========${NC}" >> "${logfile}"

# Its needed to ensure that the "one_env" file it's where it should be.
# For that, everything inside "one_env" will be removed, because "one-context"
# have a weird behavior.
chmod 777 /var/run/one-context/*
rm -rf /var/run/one-context/
/usr/local/bin/bash /usr/sbin/one-contextd

# The script will continue if the following function allow it
check_nics_condition

#==========================================================================================
# 3.1. Is this pfsense for HA?
#==========================================================================================

# Check the VM hostname
new_hostname=`grep -w "SET_HOSTNAME" $one_env | cut -d'"' -f2`

# Is this pfsense for standalone or HA?
eth0_vrouter_new_ip=`grep -w "ETH0_VROUTER_IP" $one_env | cut -d \" -f2`
if [[ $eth0_vrouter_new_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  ## The "one_env" file includes the context var "ETH0_VROUTER_IP"
  ## So, this pfsense was instantiated for HA purposes

  ## Check if this is the first iteration of the script
  if [ -f $config_primary ] || [ -f $config_secondary ]; then
    ### This is the first iteration of the script
    ### Some things needs to be done
    DATE=$(date +%Y-%m-%d-T%H:%M:%S)
    echo -e "${DATE}: The ${GREEN}\"$new_hostname\"${NC} has the one_env file with the context var ${GREEN}\"ETH0_VROUTER_IP\"${NC} for HA" >> "${logfile}"
    echo -e "${DATE}: Start looking for its role ${GREEN}\"<primary|secondary>\"${NC}" >> "${logfile}"

    ### Determinate if is a primary or secondary node
    last_character=${new_hostname: -1}
    if [ $last_character -eq 0 ]; then
      ##### This is a pfsense primary node
      ##### Applying "config.xml" for pfsense primary node in HA
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: The vrouter has ${GREEN}\"$last_character\"${NC} at the end of the hostname, so is the ${GREEN}primary${NC} node" >> "${logfile}"
      echo -e "${DATE}: Moving to production the ${GREEN}\"$config_primary\"${NC} file" >> "${logfile}"
      apply_config_primary

      ##### Enable flag for primary node
      primary_node="1"
    fi

    if [ $last_character -eq 1 ]; then
      ##### This is a pfsense secondary node
      ##### Applying "config.xml" for pfsense secondary node in HA
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: The vrouter has ${GREEN}\"$last_character\"${NC} at the end of the hostname, so is the ${GREEN}secondary${NC} node" >> "${logfile}"
      echo -e "${DATE}: Moving to production the ${GREEN}\"$config_secondary\"${NC} file" >> "${logfile}"
      apply_config_secondary

      ##### Enable flag for primary node
      secondary_node="1"
    fi

  fi

else
  ## The "one_env" does not include the context var "ETH0_VROUTER_IP"
  ## So, this pfsense was instantiated for single node purposes

  ## Check if this is the first iteration of the script
  if [ -f $config_standalone ]; then
    ### Applying "config.xml" for pfsense single node
    DATE=$(date +%Y-%m-%d-T%H:%M:%S)
    echo -e "${DATE}: The ${GREEN}\"$new_hostname\"${NC} has the one_env file without the context var ${GREEN}\"ETH0_VROUTER_IP\"${NC}, is a single node" >> "${logfile}"
    echo -e "${DATE}: Moving to production the ${GREEN}\"$config_standalone\"${NC} file" >> "${logfile}"
    apply_config_standalone

    ### Enable flag for single node
    standalone="1"
  fi

fi

#==========================================================================================
# 3.2. Update "local_one_env" from "config.xml"
#==========================================================================================

# Update vars from "config.xml" to the "local_one_env"

## ETH0_GATEWAY
### Gather eth0_gw from pfsense "config.xml"
eth0_old_gw_linenumber=`grep -oEn '<gateway>*[0-9]+' $config | sed -n 1p | cut -d ":" -f1`
eth0_old_gw=`sed -n ${eth0_old_gw_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
### Update ETH0_GATEWAY
sed -i -r "s#ETH0_GATEWAY=.*#ETH0_GATEWAY=\"$eth0_old_gw\"#" $local_one_env

## ETH0_IP
### Gather eth0_ip from pfsense "config.xml"
ETHX_IP=ETH0_IP
get_ethx_ip
eth0_old_ip=$ethx_old_ip
### Update ETH0_IP
sed -i -r "s#ETH0_IP=.*#ETH0_IP=\"$eth0_old_ip\"#" $local_one_env

## ETH1_IP
### Gather eth1_ip from pfsense "config.xml"
ETHX_IP=ETH1_IP
get_ethx_ip
eth1_old_ip=$ethx_old_ip
### Update ETH1_IP
sed -i -r "s#ETH1_IP=.*#ETH1_IP=\"$eth1_old_ip\"#" $local_one_env

## ETH0_MASK (CIDR_to_Netmask)
### Get eth0_mask_cidr from "config.xml"
eth0_old_mask_cidr_linenumber=`grep -oEn '<subnet>' $config | sed -n 1p | cut -d ":" -f1`
eth0_old_mask_cidr=`sed -n ${eth0_old_mask_cidr_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
export IP_CIDR="${eth0_old_ip}/${eth0_old_mask_cidr}"
set_variables
detect_cidr
eth0_old_mask=$(print_subnet | awk -F '/' '{print $NF}')
### Update ETH0_MASK
sed -i -r "s#ETH0_MASK=.*#ETH0_MASK=\"$eth0_old_mask\"#" $local_one_env

## ETH1_MASK (CIDR_to_Netmask)
### Get eth1_mask_cidr from "config.xml"
eth1_old_mask_cidr_linenumber=`grep -oEn '<subnet>' $config | sed -n 2p | cut -d ":" -f1`
eth1_old_mask_cidr=`sed -n ${eth1_old_mask_cidr_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
export IP_CIDR="${eth1_old_ip}/${eth1_old_mask_cidr}"
set_variables
detect_cidr
eth1_old_mask=$(print_subnet | awk -F '/' '{print $NF}')
### Update ETH1_MASK
sed -i -r "s#ETH1_MASK=.*#ETH1_MASK=\"$eth1_old_mask\"#" $local_one_env

## ETH1_NETWORK
### Gather old eth1_net from pfsense "config.xml"
eth1_old_net_linenumber=`grep -oEn '<local_network>' $config | head -n 1 | cut -d ":" -f1`
eth1_old_net=`sed -n ${eth1_old_net_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}' | awk -F '/' '{print $1}'`
### Update ETH0_GATEWAY
sed -i -r "s#ETH1_NETWORK=.*#ETH1_NETWORK=\"$eth1_old_net\"#" $local_one_env

## ETH0_VROUTER_IP, ETH1_VROUTER_IP, ETH2_IP, ETH2_MASK
if [ $primary_node -eq 1 ] || [ $secondary_node -eq 1 ]; then
  ### This pfsense is in HA (at least one of the previous flags are enabled)

  ### Gather old eth0_vrouter_ip from pfsense "config.xml"
  ETHX_VROUTER_IP=ETH0_VROUTER_IP
  string=`grep -nw "WAN VIP CARP" $config | awk '{print $1}'`
  get_ethx_vrouter_ip
  eth0_vrouter_old_ip=$ethx_vrouter_old_ip
  sed -i -r "s#ETH0_VROUTER_IP=.*#ETH0_VROUTER_IP=\"$eth0_vrouter_old_ip\"#" $local_one_env

  ### Gather old eth1_vrouter_ip from pfsense "config.xml"
  ETHX_VROUTER_IP=ETH1_VROUTER_IP
  string=`grep -nw "LAN VIP CARP" $config | awk '{print $1}'`
  get_ethx_vrouter_ip
  eth1_vrouter_old_ip=$ethx_vrouter_old_ip
  sed -i -r "s#ETH1_VROUTER_IP=.*#ETH1_VROUTER_IP=\"$eth1_vrouter_old_ip\"#" $local_one_env

  ### ETH2_IP
  #### Gather eth2_ip from pfsense "config.xml"
  ETHX_IP=ETH2_IP
  get_ethx_ip
  eth2_old_ip=$ethx_old_ip
  #### Update ETH2_IP
  sed -i -r "s#ETH2_IP=.*#ETH2_IP=\"$eth2_old_ip\"#" $local_one_env

  ### ETH2_MASK (CIDR_to_Netmask)
  #### Get eth2_mask_cidr from "config.xml"
  eth2_old_mask_cidr_linenumber=`grep -oEn '<subnet>' $config | sed -n 3p | cut -d ":" -f1`
  eth2_old_mask_cidr=`sed -n ${eth2_old_mask_cidr_linenumber}p $config | awk -F '>' '{print $2}' | awk -F '<' '{printf $1}'`
  export IP_CIDR="${eth2_old_ip}/${eth2_old_mask_cidr}"
  set_variables
  detect_cidr
  eth2_old_mask=$(print_subnet | awk -F '/' '{print $NF}')
  #### Update ETH2_MASK
  sed -i -r "s#ETH1_MASK=.*#ETH1_MASK=\"$eth2_old_mask\"#" $local_one_env

  ## PASSWORD
  force_change_password
fi

## PASSWORD for standalone pfsense at first boot
if [ $standalone -eq 1 ]; then
  force_change_password
fi

#==========================================================================================
# 3.3. Compare "one_env" with "local_one_env"
#==========================================================================================

# Check if the "local_env" is the same as the current "one_env"
diff $one_env $local_one_env
if [ $? -ne 0 ]; then
##
## Files are differents, so the BIG IF needs to check some stuffs
##
    #==========================================================================================
    ## 3.3.1. Set vnet0~eth0 (WAN IP)/mask/gateway/openvpn-server
    #==========================================================================================

    # Check if changed the eth0_ip

    ## Gather eth0_old_ip and eth0_new_ip
    ETHX_IP=ETH0_IP
    get_ethx_ip
    eth0_old_ip=$ethx_old_ip
    eth0_new_ip=$ethx_new_ip

    ## Compare both strings
    if [ ! -z $eth0_new_ip ] && [ $eth0_old_ip != $eth0_new_ip ]; then
      ### Both strings are differents, so there was a change in the eth0_ip and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth0_ip from ${YELLOW}\"${eth0_old_ip}\"${NC} to ${GREEN}\"${eth0_new_ip}\"${NC}" >> "${logfile}"
      sed -i -r "s#<ipaddr>$eth0_old_ip</ipaddr>#<ipaddr>$eth0_new_ip</ipaddr>#" $config

      ### Update the interface name
      get_ethx_name
      sed -i -r "s#<if>vtnet0</if>#<if>$eth0_name</if>#" $config
      sed -i -r "s#<if>re0</if>#<if>$eth0_name</if>#" $config

      ### Due to eth0_ip change, restart openvpn-server "server1" service
      #change_ovpn_client_wan_ip
      restart-ovpn-server
      #restart-ovpn-client

      ### Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    # Check if changed the eth0_gateway

    ## Gather eth0_gw
    get_eth0_gw

    ## Compare both strings
    if [ ! -z $eth0_new_gw ] && [ $eth0_old_gw != $eth0_new_gw ]; then
      ### Both strings are differents, so there was a change in the eth0_gw and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth0_gw from ${YELLOW}\"${eth0_old_gw}\"${NC} to ${GREEN}\"${eth0_new_gw}\"" >> "${logfile}"
      sed -i -r "${eth0_old_gw_linenumber}s#<gateway>$eth0_old_gw</gateway>#<gateway>$eth0_new_gw</gateway>#" $config

      ### Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    # Check if changed the eth0_mask_cidr

    ## Gather eth0_mask_cidr
    ETHX_MASK=ETH0_MASK
    get_ethx_mask
    ethx_mask=eth0_mask
    ethx_new_mask_cidr=`netmask_to_cidr $ethx_new_mask`
    eth0_old_mask_cidr=$ethx_old_mask_cidr
    eth0_new_mask_cidr=$ethx_new_mask_cidr

    ## Compare both strings
    if [ ! -z $eth0_new_mask ] && [ $eth0_old_mask_cidr != $eth0_new_mask_cidr ]; then
      ### Both strings are differents, so there was a change in the eth0_mask_cidr and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth0_mask_cidr from ${YELLOW}\"/${eth0_old_mask_cidr}\"${NC} to ${GREEN}\"/${eth0_new_mask_cidr}\"${NC}" >> "${logfile}"
      sed -i -r "${eth0_old_mask_cidr_linenumber}s#<subnet>.*</subnet>#<subnet>$eth0_new_mask_cidr</subnet>#" $config

      ### Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    #==========================================================================================
    ## 3.3.2. Set vnet1~eth1 (LAN IP)/mask/openvpn-server
    #==========================================================================================

    # Check if changed the eth1_ip

    ## Gather eth1_old_ip and eth1_new_ip
    ETHX_IP=ETH1_IP
    get_ethx_ip
    eth1_old_ip=$ethx_old_ip
    eth1_new_ip=$ethx_new_ip

    ## Compare both strings
    if [ ! -z $eth1_new_ip ] && [ $eth1_old_ip != $eth1_new_ip ]; then
      ### Both strings are differents, so there was a change in the eth1_ip and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth1_ip from ${YELLOW}\"${eth1_old_ip}\"${NC} to ${GREEN}\"${eth1_new_ip}\"${NC}" >> "${logfile}"
      sed -i -r "s#<ipaddr>$eth1_old_ip</ipaddr>#<ipaddr>$eth1_new_ip</ipaddr>#" $config

      ### Update the interface name
      get_ethx_name
      sed -i -r "s#<if>vtnet1</if>#<if>$eth1_name</if>#" $config
      sed -i -r "s#<if>re1</if>#<if>$eth1_name</if>#" $config

      # Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    # Check if changed the eth1_mask_cidr

    ## Gather eth1_mask_cidr
    ETHX_MASK=ETH1_MASK
    get_ethx_mask
    ethx_mask=eth1_mask
    ethx_new_mask_cidr=`netmask_to_cidr $ethx_new_mask`
    eth1_old_mask_cidr=$ethx_old_mask_cidr
    eth1_new_mask_cidr=$ethx_new_mask_cidr

    ## Compare both strings
    if [ ! -z $eth1_new_mask ] && [ $eth1_old_mask_cidr != $eth1_new_mask_cidr ]; then
      ### Both strings are differents, so there was a change in the eth1_mask_cidr and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth1_mask_cidr from ${YELLOW}\"/${eth1_old_mask_cidr}\"${NC} to ${GREEN}\"/${eth1_new_mask_cidr}\"${NC}" >> "${logfile}"
      sed -i -r "${eth1_old_mask_cidr_linenumber}s#<subnet>.*</subnet>#<subnet>$eth1_new_mask_cidr</subnet>#" $config

      ### Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    ## Check if changed the eth1_net
    get_eth1_net

    ## Compare both strings
    if [ ! -z $eth1_new_net ] && [ $eth1_old_net != $eth1_new_net ]; then
      ### Both strings are differents, so there was a change in the eth1_net and needs to be updated
      set_ovpn_server_local_network

      ### Restart openvpn server
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Restarting openvpn-server \"server1\"" >> "${logfile}"
      restart-ovpn-server
      #restart-ovpn-client

      # Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    #==========================================================================================
    ## 3.3.3. Set Hostname
    #==========================================================================================

    # Check if changed the hostname

    ## Gather old_hostname and new_hostname
    old_hostname=`grep -w "hostname" $config | cut -d'>' -f2 | cut -d'<' -f1`
    new_hostname=`grep -w "SET_HOSTNAME" $one_env | cut -d'"' -f2`

    # Compare both strings
    if [ ! -z $new_hostname ] && [ $old_hostname != $new_hostname ]; then
      # Both strings are differents, so there was a change in hostname and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating hostname from ${YELLOW}\"${old_hostname}\"${NC} to ${GREEN}\"${new_hostname}\"${NC}" >> "${logfile}"
      sed -i -r "s#<hostname>$old_hostname</hostname>#<hostname>$new_hostname</hostname>#" $config

      # Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    #==========================================================================================
    ## 3.3.4. Change domain
    #==========================================================================================

    # Check if changed the hostname

    ## Gather old_domain and new_domain
    old_domain=`grep -w "domain" $config | cut -d'>' -f2 | cut -d'<' -f1`
    new_domain=`grep -w "\SET_DOMAIN" $one_env | cut -d'"' -f2`

    # Compare both strings
    if [ ! -z $new_domain ] && [ $old_domain != $new_domain ]; then
      # Both strings are differents, so there was a change in the domain and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating domain from ${YELLOW}\"${old_domain}\"${NC} to ${GREEN}\"${new_domain}\"${NC}" >> "${logfile}"
      sed -i -r "s#<domain>$old_domain</domain>#<domain>$new_domain</domain>#" $config

      # Enable the flag to reload the pfsense configuration
      reset_config="1"
    fi

    #==========================================================================================
    ## 3.3.5. Change root (admin) password
    #==========================================================================================

    # Check if changed the password

    ## Gather old_root_pass and new_root_pass
    old_root_pass=`grep PASSWORD $local_one_env | grep -v ROOT | cut -d'"' -f2`
    new_root_pass=`grep PASSWORD $one_env | grep -v ROOT | cut -d'"' -f2`

    # Compare both strings
    if [ ! -z $new_root_pass ] && [ $old_root_pass != $new_root_pass ]; then
      # Both strings are differents, so there was a change in the root_pass and needs to be updated
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating root_pass from ${YELLOW}\"${old_root_pass}\"${NC} to ${GREEN}\"${new_root_pass:0:1}****${new_root_pass: -1}\"${NC}" >> "${logfile}"
      printf "admin\n${new_root_pass}\n${new_root_pass}\n" | pfSsh.php playback changepassword
      sleep 2

      # Enable the flag for root_pass changed
      reset_config_2="1"
    fi

    #==========================================================================================
    ## 3.3.6. Pfsense High Availability
    #==========================================================================================

    # Check if HA is enabled

    ## Gather HA config status
    grep -nw "<pfsyncenabled>on</pfsyncenabled>" $config
    if [ $? -eq 0 ]; then

      ### HA is enabled and this should be the primary pfsense

      ### Check if changed the eth0_vrouter_ip

      #### Gather eth0_vrouter_old_ip and eth0_vrouter_new_ip
      ETHX_VROUTER_IP=ETH0_VROUTER_IP
      string=`grep -nw "WAN VIP CARP" $config | awk '{print $1}'`
      get_ethx_vrouter_ip
      eth0_vrouter_old_ip=$ethx_vrouter_old_ip
      eth0_vrouter_new_ip=$ethx_vrouter_new_ip

      #### Compare both strings
      if [ ! -z $eth0_vrouter_new_ip ] && [ $eth0_vrouter_old_ip != $eth0_vrouter_new_ip ]; then

        ##### Both strings are differents, so there was a change in the eth0_vrouter_ip and needs to be updated
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: Updating eth0_vrouter_ip from ${YELLOW}\"${eth0_vrouter_old_ip}\"${NC} to ${GREEN}\"${eth0_vrouter_new_ip}\"${NC}" >> "${logfile}"
        sed -i -r "s#<subnet>$eth0_vrouter_old_ip</subnet>#<subnet>$eth0_vrouter_new_ip</subnet>#" $config

        ##### Make sure that be using the same mask as eth0_new_mask_cidr
        string=`grep -nw "WAN VIP CARP" $config | awk '{print $1}'`
        linenumber=${string::-1}
        vip_wan_subnet_bits_linenumber=$(expr $linenumber + 2)
        sed -i -r "${vip_wan_subnet_bits_linenumber}s#<subnet_bits>.*</subnet_bits>#<subnet_bits>${eth0_new_mask_cidr}</subnet_bits>#" $config

        ##### As the eth0_vrouter_ip changed, then the last octet also changed and need to be updated
        eth0_vrouter_last_octet=`echo "$eth0_vrouter_new_ip" | sed 's/^.*\.\([^.]*\)$/\1/'`
        string=`grep -nw "WAN VIP CARP" $config | awk '{print $1}'`
        linenumber=${string::-1}
        vip_wan_vhid_linenumber=$(expr $linenumber - 5)
        sed -i -r "${vip_wan_vhid_linenumber}s#<vhid>.*</vhid>#<vhid>${eth0_vrouter_last_octet}</vhid>#" $config

        ##### Due to eth0_vrouter_ip change, OpenVPN config needs to be updated
        get_wan_vip_uniqid
        set_ovpn_server_wan_vip
        set_ovpn_server_local_network
        #update_ovpn_client_config
        restart-ovpn-server
        #restart-ovpn-client

        # Enable the flag to reload the pfsense configuration
        reset_config="1"
      fi

      ### Check if changed the eth1_vrouter_ip

      #### Gather eth1_vrouter_old_ip and eth1_vrouter_new_ip
      ETHX_VROUTER_IP=ETH1_VROUTER_IP
      string=`grep -nw "LAN VIP CARP" $config | awk '{print $1}'`
      get_ethx_vrouter_ip
      eth1_vrouter_old_ip=$ethx_vrouter_old_ip
      eth1_vrouter_new_ip=$ethx_vrouter_new_ip

      #### Compare both strings
      if [ ! -z $eth1_vrouter_new_ip ] && [ $eth1_vrouter_old_ip != $eth1_vrouter_new_ip ]; then

        ##### Both strings are differents, so there was a change in the eth1_vrouter_ip and needs to be updated
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: Updating eth1_vrouter_ip from ${YELLOW}\"${eth1_vrouter_old_ip}\"${NC} to ${GREEN}\"${eth1_vrouter_new_ip}\"${NC}" >> "${logfile}"
        sed -i -r "s#<subnet>$eth1_vrouter_old_ip</subnet>#<subnet>$eth1_vrouter_new_ip</subnet>#" $config

        ##### Make sure that be using the same mask as eth1_new_mask_cidr
        string=`grep -nw "LAN VIP CARP" $config | awk '{print $1}'`
        linenumber=${string::-1}
        vip_lan_subnet_bits_linenumber=$(expr $linenumber + 2)
        sed -i -r "${vip_lan_subnet_bits_linenumber}s#<subnet_bits>.*</subnet_bits>#<subnet_bits>${eth1_new_mask_cidr}</subnet_bits>#" $config

        ##### As the eth1_vrouter_ip changed, then the last octet also changed and need to be updated
        eth1_vrouter_last_octet=`echo "$eth1_vrouter_new_ip" | sed 's/^.*\.\([^.]*\)$/\1/'`
        string=`grep -nw "LAN VIP CARP" $config | awk '{print $1}'`
        linenumber=${string::-1}
        vip_lan_vhid_linenumber=$(expr $linenumber - 5)
        sed -i -r "${vip_lan_vhid_linenumber}s#<vhid>.*</vhid>#<vhid>${eth1_vrouter_last_octet}</vhid>#" $config
      fi

    fi

    if [ $primary_node -eq 1 ] || [ $secondary_node -eq 1 ]; then
      ## This pfsense is in HA
      ## Check if changed the eth2_ip

      ## Gather eth2_old_ip and eth2_new_ip
      ETHX_IP=ETH2_IP
      get_ethx_ip
      eth2_old_ip=$ethx_old_ip
      eth2_new_ip=$ethx_new_ip

      ## Compare both strings
      if [ ! -z $eth2_new_ip ] && [ $eth2_old_ip != $eth2_new_ip ]; then
        ### Both strings are differents, so there was a change in the eth2_ip and needs to be updated
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: Updating eth2_ip from ${YELLOW}\"${eth2_old_ip}\"${NC} to ${GREEN}\"${eth2_new_ip}\"${NC}" >> "${logfile}"
        sed -i -r "s#<ipaddr>$eth2_old_ip</ipaddr>#<ipaddr>$eth2_new_ip</ipaddr>#" $config

        ### Update the interface name
        get_ethx_name
        sed -i -r "s#<if>vtnet2</if>#<if>$eth2_name</if>#" $config
        sed -i -r "s#<if>re2</if>#<if>$eth2_name</if>#" $config

        # Enable the flag to reload the pfsense configuration
        reset_config="1"
      fi

      # Check if changed the eth2_mask_cidr

      ## Gather eth2_mask_cidr
      ETHX_MASK=ETH2_MASK
      get_ethx_mask
      ethx_mask=eth2_mask
      ethx_new_mask_cidr=`netmask_to_cidr $ethx_new_mask`
      eth2_old_mask_cidr=$ethx_old_mask_cidr
      eth2_new_mask_cidr=$ethx_new_mask_cidr

      ## Compare both strings
      if [ ! -z $eth2_new_ip ] && [ $eth2_old_ip != $eth2_new_ip ]; then
      eth2_new_net=`grep ETH2_NETWORK $one_env | cut -d'"' -f2`
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Updating eth2_net on firewall rules for PFSYNC interface" >> "${logfile}"
      sed -i -r "s#<address>.*</address>#<address>${eth2_new_net}/${eth2_old_mask_cidr}</address>#" $config

      # Enable the flag to reload the pfsense configuration
      reset_config="1"
      fi

      if [ ! -z $eth2_new_mask ] && [ $eth2_old_mask_cidr != $eth2_new_mask_cidr ]; then
        ### Both strings are differents, so there was a change in the eth2_mask_cidr and needs to be updated
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: Updating eth0_mask_cidr from ${YELLOW}\"/${eth2_old_mask_cidr}\"${NC} to ${GREEN}\"/${eth2_new_mask_cidr}\"${NC}" >> "${logfile}"
        sed -i -r "${eth2_old_mask_cidr_linenumber}s#<subnet>.*</subnet>#<subnet>$eth2_new_mask_cidr</subnet>#" $config

        # Enable the flag to reload the pfsense configuration
        reset_config="1"
      fi

      ## Gather eth2_new_net
      if [ ! -z $eth2_new_mask ] && [ $eth2_old_mask_cidr != $eth2_new_mask_cidr ]; then
        eth2_new_net=`grep ETH2_NETWORK $one_env | cut -d'"' -f2`
        DATE=$(date +%Y-%m-%d-T%H:%M:%S)
        echo -e "${DATE}: Updating eth2_mask_cidr on firewall rules for PFSYNC interface" >> "${logfile}"
        sed -i -r "s#<address>.*</address>#<address>${eth2_new_net}/${eth2_new_mask_cidr}</address>#" $config

        # Enable the flag to reload the pfsense configuration
        reset_config="1"
      fi
    fi

    #==========================================================================================
    ## 3.3.7. Reload pfsense configuration if necessary
    #==========================================================================================

    # Check the status of the flag
    if [ $reset_config -eq 1 ] && [ $reset_config_2 -eq 0 ]; then
      ## The reload flag is activated, so pfsense configuration must be reloaded
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Reloading pfsense configuration" >> "${logfile}"
      /etc/rc.reload_all start

      ## Giving it a timeout
      sleep 5

      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: pfSense config have been updated through the context vars${NC}" >> "${logfile}"
      echo -e "${DATE}: Updating the \"local_one_env\" with \"one_env\" content" >> "${logfile}"
      ## Update the "local_one_env" with all new context variables from "one_env"
      cp $one_env $local_one_env
    fi

    if [ $reset_config -eq 0 ] && [ $reset_config_2 -eq 1 ]; then
      ## The reload flag2 is activated, so pfsense configuration must be reloaded
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Reloading pfsense configuration" >> "${logfile}"
      /etc/rc.reload_all start

      ## Giving it a timeout
      sleep 5

      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: pfSense config have been updated due to password change" >> "${logfile}"
      echo -e "${DATE}: Updating the \"local_one_env\" with \"one_env\" content" >> "${logfile}"
      ## Update the "local_one_env" with all new context variables from "one_env"
      cp $one_env $local_one_env
    fi

    if [ $reset_config -eq 1 ] && [ $reset_config_2 -eq 1 ]; then
      ## Both reload flag are activated, pfsense configuration must be reloaded
      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: Reloading pfsense configuration" >> "${logfile}"
      /etc/rc.reload_all start

      ## Giving it a timeout
      sleep 5

      DATE=$(date +%Y-%m-%d-T%H:%M:%S)
      echo -e "${DATE}: pfSense config have been updated through the context vars" >> "${logfile}"
      echo -e "${DATE}: pfSense config have been updated due to password change" >> "${logfile}"
      echo -e "${DATE}: Updating the \"local_one_env\" with \"one_env\" content" >> "${logfile}"
      ## Update the "local_one_env" with all new context variables from "one_env"
      cp $one_env $local_one_env
    fi
##
## Closing the BIG IF
##
fi

###########################################################################################
# 3.4. Firewall rules for PFSYNC
###########################################################################################

# Create the necessary rules for the PFSYNC

if [ $primary_node -eq 1 ] || [ $secondary_node -eq 1 ]; then
  ## This pfsense is in HA

  ## Gather eth2_new_net
  eth2_new_net=`grep ETH2_NETWORK $one_env | cut -d'"' -f2`

  ## Gather eth2_mask_cidr
  eth2_new_mask=`cat $one_env | grep -w ETH2_MASK | cut -d \" -f2`
  eth2_new_mask_cidr=`netmask_to_cidr $eth2_new_mask`

#  ## Add firewall rules for PFSYNC via EasyRule
#  ## easyrule pass <interface> <protocol> <source address> <destination address> [destination port]
#  ### Rule #1: Pass login to the WebbUI
#  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
#  echo -e "${DATE}: Creating rules for PFSYNC via EasyRule" >> "${logfile}"
#  echo -e "${DATE}: easyrule pass opt1 tcp ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr} 8443" >> "${logfile}"
#  easyrule pass opt1 tcp ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr} 8443 &> /tmp/output.txt
#  echo -e "${DATE}: $(cat /tmp/output.txt)" >> "${logfile}"
#  sleep 2
#
#  ### Rule #2: Pass PFSYNC protocol
#  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
#  echo -e "${DATE}: easyrule pass opt1 pfsync ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr}" >> "${logfile}"
#  easyrule pass opt1 pfsync ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr} &> /tmp/output.txt
#  echo -e "${DATE}: $(cat /tmp/output.txt)" >> "${logfile}"
#  sleep 2
#
#  ### Rule #3: Pass ICMP echo-req
#  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
#  echo -e "${DATE}: easyrule pass opt1 icmp ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr}" >> "${logfile}"
#  easyrule pass opt1 icmp ${eth2_new_net}/${eth2_new_mask_cidr} ${eth2_new_net}/${eth2_new_mask_cidr} &> /tmp/output.txt
#  echo -e "${DATE}: $(cat /tmp/output.txt)" >> "${logfile}"
#  sleep 2

  if [ $primary_node -eq 1 ]; then
  ## Reboot the system now
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Rebooting primary node" >> "${logfile}"
  reboot
  fi

  if [ $secondary_node -eq 1 ]; then
  ## Reboot the system after 1 min of executed the command
  ## Its needed that primary node apply first the changes
  ## Thats why the following command add a delay to the reboot of the secondary node
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Rebooting secondary node" >> "${logfile}"
  shutdown -r +1
  fi
fi

if [ $standalone -eq 1 ]; then
  ## Reboot the system now
  DATE=$(date +%Y-%m-%d-T%H:%M:%S)
  echo -e "${DATE}: Rebooting standalone pfsense" >> "${logfile}"
  reboot
fi

# Make sure that "local_one_env" is a copy of "one_env" file at the end of the script
cp $one_env $local_one_env

# Exiting from the script
check_log_last_line
exit 0