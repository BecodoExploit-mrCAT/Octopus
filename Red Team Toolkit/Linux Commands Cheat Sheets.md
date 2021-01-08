# ***NIX COMMANDS**


## **Linux Network Commands**	

#### Network connections
```
watch ss -tp 	
```

#### Tcp connections -anu=udp 
```
netstat -ant 	
```

#### Connections with PIDs 
```
netstat -tulpn 	
```

#### Established connections
```
lsof -i 	
```

#### Access windows smb share 
```
smb://<ip>/share 	
```

#### Mount Windows share 
```
share user x.x.x.x c$ 	
```

#### SMB connect 
```
smbclient -0 user\\\\<ip>\\<share> 	
```

#### Set IP and netmask 
```
ifconfig eth# <ip>/<cidr> 	
```

#### Set virtual interface 
```
ifconfig eth0:1 <ip>/<cidr> 	
```

#### Set GW 
```
route add default gw <gw_ip> 	
```

#### Change MTU size 
```
ifconfig eth# mtu [size]
```
	
#### Change MAC 
```
export MAC=XX:XX:XX:XX:XX:XX 	
```

#### Change MAC 
```
ifconfig <int> hw ether <MAC> 	
```

#### Backtrack MAC changer 
```
macchanger -m <MAC> <int> 	
```

#### Built-in wifi scanner 
```
iwlist <int> scan 	
```

#### Domain lookup for IP 
```
dig -x <ip>
```

#### Domain lookup for IP 
```
host <ip>	 
```

#### Domain SRV lookup 
```
host -t SRV_<service>_tcp.url.com 	 
```
 	
#### DNS Zone Xfer 
```
dig @<ip> domain -t AXFR 	 
```
 	
#### DNS Zone Xfer 
```
host -l <domain> <namesvr> 	 
```
 	
#### Print existing VPN keys 
```
ip xfrm state list 	 
```
 	
#### Adds 'hidden' interface 
```
ip addr add <ip>/<cidr> dev eth0	 
```
 	
#### List DHCP assignments 
```
/var/log/messages | grep DHCP 	 
```
 	
#### Block ip:port 
```
tcpkill host<ip> and port<port> 	 
```
 	
#### Turn on IP Forwarding 
```
echo "1" > /proc/sys/net/ipv4/ip_forward 	 
```
 	
#### Add DNS Server
```
echo "nameserver x.x.x.x" >> /etc/resolv.conf	
```  
  
## **LINUX SYSTEM INFO** 	

#### Get hostname for <ip> 
```
nbtstat -A <ip>	
```

#### Current username 
```
id  
```

#### Logged on users 
```
w  
```

#### User information 
``` 
who -a   
```	

#### Last users logged on  
```
last -a  
``` 	

#### Process listing (top)  
```
ps -ef   
```	

#### Disk usage (free)  
```
df -h   
```	

#### Kernel version/CPU info  
```
uname -a   
```	

#### Mounted file Systems  
```
mount   
```	

#### Show list of users  
```
getent passwd 	  
```

#### Add to PATH variable  
```
PATH=$PATH:/home/mypath   
```	

#### Kills process with <pid>  
```
kill <pid>  
```	

#### Show OS info  
```
cat /etc/issue 	  
```

#### Show OS version info  
```
cat /etc/*release*  
```	

#### Show kernel info  
```
cat /proc/version   
```	

#### Installed pkgs (Redhat)  
```
rpm --query -all   
```	

#### Install RPM (-e=remove)  
```
rpm -ivh *.rpm 	  
```

#### Installed pkgs (Ubuntu)  
```
dpkg -get-selections 	  
```

#### Install DEB (-r=remove)   
```
dpkg -I *.deb 	  
```

#### Installed pkgs (Solaris)  
```
pkginfo   
```	

#### Show location of executable  
```
which <tscsh/csh/ksh/bash>  
```

#### Disable <shell>, force bash 
```
chmod 750 <tcsh/csh/ksh>  
```	




## **Linux Utility Commands**

#### Grab url 
```
wget http://<url> -O url.txt -o /dev/null 
```	

#### Remote Desktop to <ip> 
```
rdesktop ip 	
```	

#### Put file 
```
scp /tmp/file user@x.x.x.x:/tmp/file	
``` 	

#### Get file 
```
scp user@ remoteip :/tmp/file /tmp/file	
``` 	

#### Add user 
```
useradd -m <user>	
``` 	

#### Change user password 
```
passwd <user>	
``` 	

#### Remove user 
```
rmuser uname	
``` 	

#### Record shell : Ctrl-D stops 
```
script -a <outfile>	
``` 	

#### Find related command 
```
apropos <subject>	
``` 	

#### View users command history 
```
history 	
```	

#### Executes line # in history 
```
! <num>	
```  
  
  
  
  
## **Linux File Commands**

#### Compare files 
```
diff filel file2 	
```	

#### Force delete of <dir> 
```
rm -rf <dir> 	
```	

#### Overwrite/delete file 
```
shred -f -u <file> 	
```	

#### Matches ref_ file timestamp 
```
touch -r <ref_file> <file> 	
```	

#### Set file timestamp 
```
touch -t YYYYMMDDHHSS <file>	
``` 	

#### List connected drives
```
sudo fdisk -l 		
```

#### Mount USB key 
```
mount /dev/sda# /mnt/usbkey 	
```	

#### Compute md5 hash 
```
md5sum -t file 		
```

#### Generate md5 hash 
```
echo -n "str" | md5sum 	
```	

#### SHAl hash of file 
```
shalsum file 	
```	

#### Sort/show unique lines
``` 
sort -u 	
```	

#### Count lines w/ "str" 
```
grep -c "str" file 	
```	

#### Create .tar from files 
```
tar cf file.tar files 	
```	

#### Extract .tar 
```
tar xf file.tar 	
```	

#### Create .tar.gz 
```
tar czf file.tar.gz files 	
```	

#### Extract .tar.gz
``` 
tar xzf file.tar.gz 	
```	

#### Create .tar.bz2 
```
tar cjf file.tar.bz2 files	
``` 	

#### Extract .tar.bz2 
```
tar xjf file.tar.bz2 	
```	

#### Compress/rename file 
```
gzip <file> 	
```	

#### Decompress file.gz 
```
gzip -d file.gz 	
```	

#### UPX packs orig.exe 
```
upx -9 -o out.exe orig.exe 	
```	

#### Create zip 
```
zip -r <zipname.zip> \Directory\* 	
```	

#### Cut block 1K-3K from file 
```
dd skip=1000 count=2000 bs=8 if=file of=file 	
```	

#### Split file into 9K chunks 
```
split -b 9K \ file prefix 	
```	

#### Win compatible txt file 
```
awk 'sub("$"."\r")' unix.txt > win.txt 	
```

#### Find PDF files 
```
find -i -name <file> -type *.pdf 	
```	

#### Search for setuid files 
```
find / -perm -4000 -o -perm -2000 -exec ls -ldb {} \; 		
```

#### Convert to *nix format 
```
dos2unix <file> 		
```

#### Determine file type/info 
```
file <file> 		
```

#### Set/Unset immutable bit
```
chattr (+/-)i <file> 		
```  
  
  
## **Linux Misc Commands**

#### Disable history logging 
```
unset HISTFILE	
``` 	

#### Record remote mic 
```
ssh user@<ip> arecord - | aplay -	
```	

#### Compile C,C++ 
```
gcc -o outfile myfile.c	
``` 	

#### Reboot (0 = shutdown) 
```
init 6	
``` 	

#### List of log files
``` 
cat /etc/*syslog*.conf | grep -v "^#'"	
```	

#### Strip links in url.com 
```
grep 'href=' file | cut -d"/" -f3 | grep <url> |sort -u	
``` 	

#### Make random 3MB file
```
dd if=/dev/urandom of=<file> bs=3145728 count=100	
```  
  
  
## **Linux "Cover Your Tracks" Commands**

#### Clear auth.log file 
```
echo "" /var/log/auth.log 
```	

#### Clear current user bash history 
```
echo "" -/.bash history 
```	

#### Delete .bash_history file 
```
rm ~/.bash histor/ -rf
``` 	

#### Clear current session history 
```
history -c 
```	

#### Set history max lines to 0 
```
export HISTFILESIZE=O 
```	

#### Set histroy max commands to 0 
```
export HISTSIZE=O 
```	

#### Disable history logging (need to logout to take effect) 
```
unset HISTFILE 	
```

#### Kills current session 
```
kill -9 $$ 
```	

#### Perrnanently send all bash history commands to /dev/null
```
ln /dev/null ~/.bash_history -sf
```  
  
  
  
## **Linux File System Structure**

#### User binaries 
```
/bin 
```	

#### Boot-up related files 
```
/boot 
```	

#### Interface for system devices 
```
/dev 
```	

#### System configuration files 
```
/etc 
```	

#### Base directory for user files
``` 
/home 	
```

#### Critical software libraries 
```
/lib 	
```

#### Third party software
```
/opt 
```	

#### System and running programs 
```
/proc 	
```

#### Home directory of root user 
```
/root 	
```

#### System administrator binaries 
```
/sbin 	
```

#### Temporary files  
```
/tmp 
```	

#### Less critical files 
``` 
/usr 
```	

#### Variable System files 
```
/var 
``` 
  
  
## **Linux Files**

#### Local users' hashes 
```
/etc/shadow 
```	

#### Local users 
```
/etc/passwd 
```	

#### Local groups 
```
/etc/group 
```	

#### Startup services 
```
/etc/rc.d 
```	

#### Service 
```
/etc/init.d 
```	

#### Known hostnames and IPs 
```
/etc/hosts 
```	

#### Full hostname with domain 
```
/etc/HOSTNAME 
```	

#### Network configuration 
```
/etc/network/interfaces 
```	

#### System environment variables 
```
/etc/profile 	
```

#### Ubuntu sources list 
```
/etc/apt/sources.list 
```	

#### Nameserver configuration 
```
/etc/resolv.conf 
```	

#### Bash history (also /root/) 
```
/home/<user>/.bash history
```	

#### Vendor-MAC lookup 
```
/usr/share/wireshark/manuf 
```	

#### SSH keystore 
```
~/.ssh/ 
```	

#### System log files (most Linux) 
```
/var/log 
```	

#### System log files (Unix) 
```
/var/adm 
```	

#### List cron files 
```
/var/spool/cron 
```	

#### Apache connection log 
```
/var/log/apache/access.log 
```	

#### Static file system info
```
/etc/fstab 	
```
