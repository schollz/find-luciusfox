#! /bin/bash
# INFO: This is a bash script to run on DD-WRT routers for sending client's RSSI signal strength to a find-lf fingerprint server
# TODO: populate inputs/parameters from find-lf cluster configuration file

# Router Credentials (DD-WRT, tested on ARM kongac v3.0-r28600M)
ip_addr="localhost" #set to your router IP address, or localhost if running on router at boot
user="" #router login username
pass="" #router login password

# FIND-LF Server Credentials
findlf_ip="" #e.g. https://lf.internalpositioning.com/reversefingerprint OR http://your-server-ip:8075/reversefingerprint
group_name="" #group name of your find cluster
scanner_name="ddwrt_1" #unique name of this instance, that will be reported to the find-lf server (access point that the RSSI values will be reported as)
scan_freq=20 #how often to report the RSSI values of all devices connected to the router, in seconds
#rssi_col=7 #not implemented yet, but some dd-wrt versions report a different number of columns in the table of connected devices

sleep 30
while true ; do
  wifi=$(/opt/bin/wget --retry-connrefused --waitretry=500 --http-user=$user --http-password=$pass -qO- http://$ip_addr/Status_Wireless.live.asp)
  wifi=$(echo "$wifi" | /opt/bin/sed -e 's/}{/ \
/g')

  wifi=$(echo "$wifi" | /opt/bin/sed -n -e 8p)
  wifi=$(echo "$wifi" | awk '{ gsub("active_wireless::", "") } 1')

  wifi=$(echo "$wifi" | /opt/bin/sed -r "s/('([[:xdigit:]]{2}[:.-]?){5}[[:xdigit:]]{2}')/\n&/g")

  wifi=$(echo "$wifi" | tr -d "'" | tail -n +2)
  wifi=$(echo "$wifi" | /opt/bin/sed "s/day,//g" | /opt/bin/sed "s/days,//g") #fixes when commas appear in lease/connection time (when client has been connnected for longer than 24 hours)

  wifi=$(echo "$wifi" | awk -F"," '{ print "{\x27mac\x27: \x27" $1 "\x27, \x27rssi\x27: " $7 "},"}')
  wifi=$(echo "$wifi" | /opt/bin/sed '$ s/.$//')

  wifi=$(echo "{'node': '""$scanner_name""',""'signals':[""$wifi""]," "'timestamp': "$(date +%s)",'group': '"$group_name"'}")
  wifi=$(echo "$wifi" | /opt/bin/sed "s/'/\"/g")

  if ! $(curl -X POST -H 'Content-Type: application/json' --output /dev/null --silent --fail -d "$wifi" -i "$findlf_ip"); then
    sleep 300 #wait if the post fails (e.g. the find-lf server that consolidates fingerprints is not running)
  fi

  sleep $scan_freq
done
