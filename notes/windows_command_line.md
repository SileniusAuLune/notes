
WINDOWS - Command Line Cheat Sheet for Administration and Networking and Hotkeys

Hot-keys
---------------------------------------

CONTROL+SHIFT+N - make new folder
F2 - rename
WIN+D - Show dekstop
WIN + M - Minimize all windows
WIN + SHIFT + M - Maximize all windows
ALT + SPACEBAR + X - Maximize
ALT + SPACEBAR + R - Restore

CTRL+ SHIFT + F10 - Shows Context Menu (Mouse Right Click Effect)
WIN + PAUSE - System Properties
WIN + L (XP) - Lock OS
WIN + R - Run Command
WIN - Start Menu 
CTRL+ESC - Start Menu 
CTRL+SHIFT+ESC - Task Manager

WIN + ARROW KEY - moves currently selected window around - I used left and right to arrange my screen


===WINDOWS:===
---------------------------------------
===GET INFORMATION===
INFORMATION: systeminfo
TO GET NETBIOS NAME: nbtstat -a 192.168.0.5
TO DISPLAY BOTH THE ETHERNET STATISTICS AND THE STATISTICS FOR ALL PROTOCOLS, TYPE THE FOLLOWING COMMAND: netstat -e -s
TO DISPLAY THE STATISTICS FOR ONLY THE TCP AND UDP PROTOCOLS, TYPE THE FOLLOWING COMMAND: netstat -s -p tcp udp
TO DISPLAY ACTIVE TCP CONNECTIONS AND THE PROCESS IDS EVERY 5 SECONDS, TYPE THE FOLLOWING COMMAND: nbtstat -o 5
TO DISPLAY ACTIVE TCP CONNECTIONS AND THE PROCESS IDS USING NUMERICAL FORM, TYPE THE FOLLOWING COMMAND: nbtstat -n -o
ROUTES: route print
IP INFO: netsh interface ip show config
WINDOWS PIPING (/I FOR CASE NOT MATTERING): command | findstr /I PATTERNorWORDorNUMBER

===PING===
PING FOREVER: ping -t 8.8.8.8
PING SMALL PACKET: ping -l 4 -t 8.8.8.8
SOURCE PING FROM 10.10.10.2: First do "ipconfig" to see your available interfaces: "ping -S 10.10.10.2 8.8.8.8"
PING ANY PORT: telnet mailbox.kossboss.com 25

===NETWORKING===
LISTENING PORTS AND PIDS: netstat -ano
LISTENING PORTS OF PID 1234 - CAN GET FROM TASK MANAGER: netstat -ano | findstr 1234
MAKE NETWORK CARDS COME UP: ncpa.cpl
ADD ROUTE: route ADD 10.1.1.0 MASK 255.255.255.0 192.168.1.8
ADD ROUTE PERSISTENT SO LASTS TILL NEXT REBOOT: route -p ADD 10.1.1.0 MASK 255.255.255.0 192.168.1.8
DELETE ROUTE - IP OF DESTINATION: route delete 10.0.0.0 

==nslookup DNS simple==
nslookup ENTER
server 8.8.8.8 TO CHANGE TO NEW SERVER
www.google.com TO SEE IF 8.8.8.8 GETS THERE AND WHAT IP IT GETS

===How to use Nslookup to verify DNS configuration=== CITATION: http://technet.microsoft.com/en-us/library/aa997324(v=exchg.65).aspx
At a command prompt, type "Nslookup", and then press ENTER. Type "server <IP address>", where IP addressis the IP address of your external DNS server. Type "set q=MX", and then press ENTER. "Type <domain name>", where domain name is the name of an external mail domain, and then press ENTER. The mail exchanger (MX) resource record for the domain that you entered should be displayed. If the MX record is not displayed, DNS is not configured to resolve external domain names.

C:\> nslookup
Default Server: pdc.corp.example.com
Address: 192.168.6.13
> server 10.255.255.255
Default Server: dns1.example.com
Address: 10.255.255.255
> set q=mx
> contoso.com.
Server: dns1.example.com
Address: 192.168.10.10
contoso.com MX preference = 10, mail exchanger = mail1.contoso.com
contoso.com MX preference = 10, mail exchanger = mail2.contoso.com
contoso.com MX preference = 10, mail exchanger = mail3.contoso.com
mail1.contoso.com internet address = 192.168.255.011
mail2.contoso.com internet address = 192.168.255.012
mail3.contoso.com internet address = 192.168.255.013

===NET command===
CITATION: http://ss64.com/nt/net_useradmin.html

SETTING SHARES
net use
net use n: /delete
net use /delete *
net use
net use o: \\192.168.2.5\share1 password /USER:kossboss
net use o: \\192.168.2.5\share1 password /USER:kossboss /PERSISTENT:yes

VIEWING REMOTE SHARES
THIS PC SHARES: net view
OTHER PC SHARES: new view 172.20.55.201

THE NET COMMAND IS USED TO MANAGE NETWORK SECURITY RESOURCES AS FOLLOWS:

VIEW USER ACCOUNT PASSWORD AND LOGON REQUIREMENTS (ALSO DISPLAYS THE MACHINE TYPE - NT SERVER OR NT WORKSTATION)
net accounts

VIEW PASSWORD AND LOGON REQUIREMENTS FOR THE NETWORK DOMAIN.
net accounts /domain

SET THE NUMBER OF MINUTES A USER HAS BEFORE BEING FORCED TO LOG OFF WHEN THE ACCOUNT EXPIRES OR VALID LOGON HOURS EXPIRE
net accounts /forcelogoff:minutes /domain

PREVENT FORCED LOGOFF WHEN USER ACCOUNTS EXPIRE
net accounts /forcelogoff:no /domain

SET THE MINIMUM NUMBER OF CHARACTERS FOR A PASSWORD. 
net accounts /minpwlen:c /domain
THE RANGE IS 0-14 CHARACTERS; THE DEFAULT IS 6 CHARACTERS.

SET THE MAXIMUM NUMBER OF DAYS THAT A PASSWORD IS VALID.
net accounts /maxpwage:dd /domain
THE RANGE IS 1-49710; THE DEFAULT IS 90 DAYS.

SET PASSWORDS TO NEVER EXPIRE.
net accounts /maxpwage:unlimited /domain

SET A MINIMUM NUMBER OF DAYS THAT MUST PASS BEFORE A USER CAN CHANGE A PASSWORD (DEFAULT = 0)
net accounts /minpwage:dd /domain

REQUIRE THAT NEW PASSWORDS BE DIFFERENT FROM 'X' NUMBER OF PREVIOUS PASSWORDS
net accounts /uniquepw:x /domain
THE RANGE FOR 'X' IS 1-24

SYNCHORONISE THE USER ACCOUNTS DATABASE (PDC AND BDC)
net accounts /sync /domain

VIEW USER ACCOUNT DETAILS
net user [/domain]

ADD USER:
net user USER PASS /add
net user USER /add

ADD A USER ACCOUNT.
net user username {password | *} /add [options] [/domain]

MODIFY A USER ACCOUNT. 
net user [username [password | *] [options]] [/domain]

DELETE A USERNAME
net user username [/delete] [/domain]

GENERATE A RANDOM PASSWORD:
net user administrator /random

ADD A WORKGROUP
net group groupname /add [/comment:"text"] [/domain]

EDIT A WORKGROUP
net group [groupname [/comment:"text"]] [/domain]

DELETE A GROUP
net group groupname /delete [/domain]

ADD A USER TO A GROUP
net group groupname username [...] /add [/domain]

DELETE A USER FROM A GROUP
net group groupname username [...] /delete [/domain]

TO VIEW, ADD OR MODIFY A LOCAL WORKGROUP REPLACE GROUP IN THE COMMANDS ABOVE WITH LOCALGROUP.

EXAMPLES
CREATE A GROUP
c:\>net localgroup spud /add

ADD TO GUESTS
c:\>net localgroup guests spud /add

THEN REMOVE
c:\>net localgroup guests spud /delete
c:\>net localgroup spud /delete


===SET INTERNET SETTINGS:===
BAT SCRIPTS @echo off IN A BAT SCRIPT MAKES IT SO THAT COMMAND IS NOT REPEATED ON THE SCREEN WHEN THE SCRIPT RUNS IT - ITS OPTIONAL


---to show info on pc:--
@echo off
netsh interface ip dump (or can netsh interface ip dump > C:\file.txt)
netsh interface ip show config
netsh interface ip show dns
netsh interface ip show udpconn
netsh interface ip show tcpconn
netsh interface ip show icmp

---to set lan ip:---
@echo off
netsh interface ip set interface name="Wireless Network Connection" newname="wifi"
netsh interface ip set address "wifi" static 192.168.1.7 255.255.255.0 192.168.1.1 1
netsh interface ipv4 set dnsserver "lan" static 208.67.222.222
netsh interface ip add dns name="lan" addr=208.67.220.220 index=2
netsh interface ip add dns name="lan" addr=8.8.8.8 index=3
netsh interface ip add dns name="lan" addr=4.2.2.2 index=4

---to set both dhcp:---
@echo off
netsh interface ip set interface name="Wireless Network Connection" newname="wifi"
netsh interface ip set interface name="Local Area Connection" newname="lan"
netsh interface ip set address "wifi" dhcp
netsh interface ip set address "lan" dhcp
netsh interface ipv4 set dnsserver "wifi" dhcp
netsh interface ipv4 set dnsserver "lan" dhcp

===START VIRTUAL BOX MACHINE: GOOD AT STARTUP===
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm Deb

===START VMWARE WORKSTATION: GOOD AT STARTUP - DID RESEARCH CANT DO WITH VMWARE PLAYER==
@echo off
chdir "C:\Program Files\VMware\VMware Workstation"
vmrun start "C:\Users\koss\Documents\Virtual Machines\FreePBX-A\FreePBX-A.vmx"
taskkill /IM vmware.exe


`schtasks`
    to schedule tasks
    
`tasklist`
    windows `ps` and lists all processes
    
`whoami`
    see what user you

`systeminfo`
    see what system info you have

