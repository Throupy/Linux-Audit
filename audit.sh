#!/bin/bash

version="1.0"
outpath="audit.txt"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
DEFAULT='\033[0m'
UL='\e[4m'



function isSudoRun {
	if [ "$EUID" -ne 0 ]
	  then echo -e "${RED}Please run as root${DEFAULT}"
	  exit
	fi
}



function echoTitle {
	# Formats title with colours and underlining
	# $1 - the title to echo
	echo"" # \n
	echo -e "$CYAN$UL[*]$DEFAULT$UL $1$DEFAULT"
	echo"" # \n
}

function getIp4Addresses {
	echoTitle "IPv4 Addresses (and range)"
	ip addr | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d ' ' -f 6
}

function getIp6Addresses {
	echoTitle "IPv6 Addresses (and range)"
	ip addr | awk -F "inet6 " '{print $2}' | cut -d ' ' -f1 | sed -r '/^\s*$/d'
}

function getDistroInformation {
	echoTitle "Distribution Information"
	cat /etc/*-release | awk 'BEGIN{FS="="} {printf "%20s --> %s\n", $1, $2}'
}

function getEnvVars {
	echoTitle "Environment Variables"
	(env || set) 2>/dev/null | awk 'BEGIN{FS="="} {printf "%20s --> %s\n", $1, $2}'
}

function getDrives {
	echoTitle "Drives Information"
	fdisk -l | head -2
}

function getMACAddresses {
	echoTitle "MAC Addresses"
	# Filter down MAC accfess to only the MAC
	macs=$(ifconfig -a | awk '/ether/ {print $2}')
	echo "--"
	# Loop through each address
	for mac in $macs;
	do
		# Convert AA:BB to AA-BB, for example
		formatted="${mac//:/-}"
		printf "Found address : $formatted\n"
		# See if oui.txt exists. oui.txt contains a mapping of mac[0:2] -> vendor name
		if [ -f "/var/lib/ieee-data/oui.txt" ]; then
			# Extract the first three parts (EG AA-BB-CC)
			firstThree=$(echo $formatted | cut -d "-" -f 1-3)
			# And try and extract the value from the file, output accordingly.
			if grep -q $firstThree /var/lib/ieee-data/oui.txt; then
				printf "Vendor : ${CYAN}$(cat /var/lib/ieee-data/oui.txt | grep $firstThree | xargs | cut -d " " -f3-)${DEFAULT}\n"
			else
				printf "Vendor : ${RED}Didn't find a vendor\n${DEFAULT}"
			fi
		fi
	echo "--"
	done

}

function getSUIDBinaries {
	echoTitle "Binaries that run at root (SUID Bit set)"
	# Start at root, type files, SUID bit set, redirect stderr to DN
	find / -type f -perm -u=s 2>/dev/null
}

function getRunningServices {
	echoTitle "Running Services"
	service --status-all | grep "+"
}

function getMOTD {
	echoTitle "MOTD Banner"
	cat /etc/motd
}

function getUsers {
	echoTitle "All Local users"
	cat /etc/passwd | cut -d ":" -f 1
}

function getNullPasswords {
	echoTitle "Any Null passwords"
	users="$(cat /etc/passwd | cut -d ":" -f 1)"
	for user in $users;
	do
		passwd -S $user | grep "NP"
	done
}

function getPath {
	echoTitle "PATH"
	# Get all the users, to loop through and test if they can write to PATH
	users=$(cat /etc/passwd | cut -d: -f1)
	IFS=:
	for p in $PATH;
	do
		# Read values from /etc/passwd for the user entry
		getent passwd | while IFS=: read -r name password uid gid gecos home shell; do
			# Try and write to path entry from the user's permissions
			sudo -u $name test -w $p && {
				# Not bad if root can write to it - expected
				if [[ $name == "root" ]]; then
					echo -e "$GREEN[OK] $name can write to $p"
				else
					# User other than root - could be bad!
					echo -e "$RED[CRITICAL] $name can write to $p - Binary hijacking possible!"
				fi
			}
		done
	done
}

function auditSSH {
	# This section reads painfully. Probably a better way of doing this.
	echoTitle "SSH Configuration"
	# Keepalive / Timeout settings
	if [ "`grep -E "TCPKeepAlive|ClientAliveInterval|ClientAliveCountMax" /etc/ssh/sshd_config | cut -d ' ' -f2 `" != "yes 0 3" ];
	then
		echo -e "${RED}[!] KeepAlive configuration not optimal. TCPKeepAlive, ClientAliveInterval and ClientAliveCountMax should be 'yes' '0' and '3' respectively${DEFAULT}"
	else
		echo -e "${GREEN}[*] KeepAlive configration is good${DEFAULT}"
	fi
	# Check default port
	if [ "`grep 'Port 22' /etc/ssh/sshd_config`" ];
	then
		echo -e "${RED}[!] SSH Running on default port (22)${DEFAULT}"
	else
		echo -e "${GREEN}[*] SSH Running on non-default port"
	fi
	# Check auth tries
	if [ "`grep MaxAuthTries /etc/ssh/sshd_config | cut -d ' ' -f 2 `" > 3 ];
	then
		echo -e "${RED}[!] MaxAuthTries is more than 3, suggest this to be equal or below 3${DEFAULT}"
	else
		echo -e "${GREEN}[*] MaxAuthTries is 3 or less."
	fi
	# Check if root can ssh
	if [ "`grep -E ^PermitRootLogin /etc/ssh/sshd_config`" != "PermitRootLogin no" ];
	then
		echo -e "${RED}[!] root login enabled${DEFAULT}"
	else
		echo -e "${GREEN}[*] root login disabled${DEFAULT}"
	fi
	# Check listening addresses
	if [ "`grep -E ^ListenAddress /etc/ssh/sshd_config`" = "" ];
	then
		echo -e "${RED}[!] ListenAddress is set to default (all addresses). Recommend change to single address to reduce number of access points${DEFAULT}"
	else
		echo -e "${GREEN}[*] ListenAddress is set to one address${DEFAULT}"
	fi
	# Check if SSH permits empty passwords
	if [ "`grep -E ^PermitEmptyPasswords /etc/ssh/sshd_config`" != "PermitEmptyPasswords no" ];
	then
		echo -e "${RED}[!] PermitEmptyPasswords should be set to no, all users should require a password"
	else
		echo -e "${GREEN}[*] PermitEmptyPasswords is set to no, all users require a password (good!) ${DEFAULT}"
	fi
	# Check host-based authentication
	if [ "`grep -E ^HostbasedAuthentication /etc/ssh/sshd_config`" != "HostbasedAuthentication no" ];
	then
		echo -e "${RED}[!] HostbasedAuthentication should be set to no, this method of authentication should be avoided "
	else
		echo -e "${GREEN}[*] HostbasedAuthentication is set to no ${DEFAULT}"
	fi
}

function worldWriteFolders {
	echoTitle "World Writeable Folders"
	BASE_DIRS="/etc /bin /sbin /usr/bin"
	found=false
	for FOLDER in $BASE_DIRS
	do
		# Find world writeable folders / files
		if [ "`find $FOLDER -type f -perm 002`" != "" ];
		then
			echo "Warning: files in ($FOLDER) are world-writeable:"
			find $FOLDER -type f -perm -002 | xargs -r ls -al
			found=true
		fi
		if [ "`find $FOLDER -type d -perm 002`" != "" ];
		then
			echo "Warning: folders in ($FOLDER) are world-writeable:"
			find $FOLDER -type d -perm -002
			found=true
		fi
	done
	if [ "$found" = false ];
	then
		echo -e "${GREEN}No world-writeable files or folders found ${DEFAULT}"
	fi
}

function checkUmask {
	# Umask determines the default files / folders permission for newly
	# created files / folders. Varies between user
	# Probably a better way of doing this
	echoTitle "UMASK Value for all users"
	users="$(cat /etc/passwd | cut -d ":" -f 1)"
	for user in $users;
	do
		if [ "`su -c 'umask' -l $user 2>/dev/null`" == "This account is currently not available." ] || 
		   [ "`su -c 'umask' -l $user 2>/dev/null`" == "" ];
		then
			continue
		fi
		printf "%-10s" "$user" ; su -c 'umask' -l $user 2>/dev/null
	done
}

function getSystemInfo {
	echoTitle "System Information"
	line="                   ->"
	echo "-------------------------------------"
	printf "Hostname %10s -> %s\n" " " "$(hostname)"
	printf "Uptime %12s -> %s\n" " " "$(uptime | awk '{print $3,$4}' | sed 's/,//')"
	printf "Manufacturer %6s -> %s\n" " " "$(cat /sys/class/dmi/id/chassis_vendor)"
	printf "Version %11s -> %s\n" " " "$(cat /sys/class/dmi/id/product_version)"
	printf "Kernel %12s -> %s\n" " " "$(uname -r)"
	printf "Arch Type %9s -> %s\n" " " "$(arch)"
	printf "OS Info %11s -> %s\n" " " "$(hostnamectl | grep "Operating System" | awk -F ': ' '{print $2}')"
	printf "CPU Name %10s -> %s\n" " " "$(awk -F':' '/^model name/ {print $2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//')"
	printf "System Main IP %4s -> %s\n" " " "$(hostname -I | cut -d ' ' -f1)"
}

function getHardwareUsage {
	echoTitle "Hardware Usage"
	printf "Memory Usage %7s -> %s\n" " " "$(free | awk '/Mem/{printf("%.2f%"), $3/$2*100}')"
	printf "Swap Usage %9s -> %s\n" " " "$(free | awk '/Swap/{printf("%.2f%"), $3/$2*100}')"
	printf "CPU Usage %10s -> %s\n" " " "$(cat /proc/stat | awk '/cpu/{printf("%.2f%\n"), ($2+$4)*100/($2+$4+$5)}' |  awk '{print $0}' | head -1)"
}

function getListeningPorts {
	echoTitle "Listening Ports"
	sudo netstat -tuwanp 2>/dev/null | awk '{print $4}' | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2
}

function getEstablishedConnections {
	echoTitle "Established Connections"
	netstat -an | grep ESTABLISHED | awk '{ printf "%s | %s --> %s \n", $1, $4, $5 }'
}

function getArpTable {
	# Why does this take 5-10 seconds?
	echoTitle "ARP Table - May take some time"
	arp -a | awk '{printf "%s --> %s\n", $2, $4}'
}

function getRouteTables {
	echoTitle "Routing Tables"
	route -n
}

echo -e "On-Host Audit Script Running at version ${CYAN}$version${DEFAULT}"


declare -A commandDescriptions=(['Get System Information']=getSystemInfo
								['Get IPv4 Addresses']=getIp4Addresses
								['Get IPv6 Addresses']=getIp6Addresses
								['Get Distribution Information']=getDistroInformation
								['Get Information About All Connected Drives']=getDrives
								['Get MAC Addresses and Vendors']=getMACAddresses
								['Get Binaries with SUID Bit Set']=getSUIDBinaries
								['Get value of the PATH Variable']=getPath
								['Get MOTD Banner']=getMOTD
								['Get Environment Variables']=getEnvVars
								['Get Running Services']=getRunningServices
								['Get All Local Users']=getUsers
								['Get Any Null Passwords']=getNullPasswords
								['Audit SSH']=auditSSH
								['Check For World Writeable Folders']=worldWriteFolders
								['Check UMASK Value']=checkUmask
								['Get Hardware Usage']=getHardwareUsage
								['Get Listening Ports']=getListeningPorts
								['Get Established Connections']=getEstablishedConnections
								['Get ARP Table Results']=getArpTable
								['Get Route Tables']=getRouteTables)


declare -A commands=(   ['getSystemInfo']=1
						['getIp4Addresses']=1
						['getIp6Addresses']=1
						['getDistroInformation']=1
						['getDrives']=1
						['getMACAddresses']=1
						['getSUIDBinaries']=1
						['getPath']=1
						['getMOTD']=1
						['getEnvVars']=1
						['getRunningServices']=1
						['getUsers']=1
						['getNullPasswords']=1
						['auditSSH']=1
						['worldWriteFolders']=1
						['checkUmask']=1
						['getHardwareUsage']=1
						['getListeningPorts']=1
						['getEstablishedConnections']=1
						['getArpTable']=1
						['getRouteTables']=1
					)

function main {
	isSudoRun
	showCommands
	performSelectedCommands
}

function showCommands {
	echoTitle "Currently Active Functionalities"
	for command in "${!commandDescriptions[@]}";
	do
		line="                                              "
		fname=${commandDescriptions[$command]}
		[[ ${commands[$fname]} = 1 ]] && res="${GREEN}ON${DEFAULT}" || res="${RED}OFF${DEFAULT}"
		printf "%s %s $res\n" "$command" "${line:${#command}}"
	done
}

function performSelectedCommands {
	for command in "${!commands[@]}"; 
	do 
		if [ ${commands[$command]} == 1 ]; then 
			$"$command"
		fi
	done
}

main