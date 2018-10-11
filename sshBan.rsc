:local bufferName "sshBuffer";
:local listName "Blacklist";
:local timeout 180d;
:local userName "user";
:local attempt 3; # Attempts for your userName

:local privateIP "192.168.";		#192.168.0.0-192.168.255.255
:local privateIPend 8;
#:local privateIP "172.16.";		#172.16.0.0-172.31.255.255
#:local privateIPend 7;
#:local privateIP "10.";			#10.0.0.0-10.255.255.255
#:local privateIPend 3;
:local firstRunCheck true;
:local attemptCounter 0;
:local prevBadIP "";

:foreach line in=[/log find buffer=$bufferName] do={
	:do {
			:local content [/log get $line message];
			:local position1 "";
			:local position2 "";
			:local badIP "";
			:local service "";
			:local user "";
			:local privatePrefix "";

			#Bruteforce SSH/Telnet/FTP/Web/Winbox
			:if ([:find $content "login failure for user"] >= 0)\
			do={
				:set position1 [:find $content "from "];
				:set position2 [:find $content " via "];
				:set badIP [:pick $content ($position1+5) $position2];
				:set privatePrefix [:pick $badIP 0 $privateIPend];

				#check #1: Is it private address?
				:if ($privatePrefix != $privateIP)\
				do={			
					:set service [:pick $content ($position2+5) [:len $content]];
					:set user [:pick $content 23 ($position1-1)];

					#check #2: Does it exist in blacklist?
					:if ([:len [/ip firewall address-list find address=$badIP and list=$listName]] <= 0)\
					do={
						:if ($firstRunCheck)\
						do={ :set firstRunCheck false; :set prevBadIP $badIP; }
						
						#check #3: Is it you or not you?
						:if ( ($userName = $user) and ($badIP = $prevBadIP) and ($attemptCounter <= $attempt) )\
						do={
							:set attemptCounter ($attemptCounter+1);
							:log warning "$user, ip $badIP is it you? Attempt #$attemptCounter";
						}
						:if ($attemptCounter >= $attempt)\
						do={
							:log warning "ip $prevBadIP is not you! It will be banned!";
							/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by sshBan ($content)";
							:log warning "ip $badIP has been banned like a bitch!";
							:set attemptCounter 0;
						}
						:if ($attemptCounter != 0 and $prevBadIP != $badIP)	do={ :set attemptCounter 0; }

						#check #4: If it's not your username - ban it
						:if ($userName != $user or [:len $user] <= 0)\
						do={
							/ip firewall address-list add list=$listName address=$badIP timeout=$timeout comment="by sshBan ($user via $service)";
							:log warning "ip $badIP has been banned ($user via $service)";
						}
					}
				}
			:set prevBadIP $badIP;#for check #3
			}
		} on-error={ :log error "sshBan script has crashed"; }
	}
:log info "sshBan script was executed properly";