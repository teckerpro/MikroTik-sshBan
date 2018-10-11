# MikroTik-sshBan
This script parses log and add to blacklist IP which caused errors by SSH, Telnet, FTP, Winbox, Web bruteforce

This script adds to the blacklist IPv4 addresses which:

- attempt find password with NOT your username via SSH/Telnet/FTP/Web/Winbox
		
		login failure for user admin from 192.0.2.1 via ssh
		login failure for user admin from 192.0.2.2 via telnet
		login failure for user admin from 192.0.2.6 via winbox

How to use

Create logging action

	/system logging action
	add memory-lines=60 name=YOUR_ACTION target=memory
	/system logging
	add action=YOUR_ACTION topics=error,critical

Create firewall rule and address-list

	/ip firewall address-list add list=YOUR_BLACKLIST
	/ip firewall raw
	add action=drop chain=prerouting comment="Drop from blacklist" in-interface=ether-YOUR_WAN_INTERFACE \
		src-address-list=YOUR_BLACKLIST	

Create script

	/system script
	add dont-require-permissions=no name=sshBan owner=admin policy=\
		ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon \
		source="PUT HERE CODE FROM sshBan.rsc"

Setup script

	bufferName is YOUR_ACTION (e.g. sshBuffer)
	listName is YOUR_BLACKLIST (e.g Blacklist)
	timeout is YOUR_TIMEOUT (e.g. 90d if you want dynamic or leave empty if you want static)
	userName is YOUR_USERNAME (e.g. john. I don't recommend use common usernames like an admin, user...)
	attempt is NUMBER_OF_ATTEMPS for login with your $userName

Create scheduler witch your own interval, start-date and start-time

	/system scheduler
	add interval=01:00:00 name=sshBan on-event="/system script run sshBan" policy=\
		ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon start-date=oct/01/2018 start-time=00:00:00




- attempt find IPsec cipher/key

		192.0.2.0 failed to get valid proposal.
		192.0.2.0 failed to pre-process ph1 packet (side: 1, status 1).
		192.0.2.0 phase1 negotiation failed.
