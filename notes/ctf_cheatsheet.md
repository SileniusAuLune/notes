CTF Cheatsheet
================================================================================

`--`
    add to any command to tell it you are no longer adding flags
    useful with files that start with `-` such as `-file.04`

`unrar`
    open rar archive
    
`tar -zxvf`
    extract file to current dir
    
`script`
    output all terminal shit to a saved file or typescript
    `script --t=<logfile> -q <script file>` to start a session and save to files
    
    
`gzip -d`
    decompress a .gz


`exiftool`
    see metadata for an image. `-r -ext` to see meta for all in dir
    
`xxd`     
    see binary 
    `binary_file to_hex_file`
    `-r -p hex_file to_binary_file`

`base 64`
    -d decode, -i input.file (-i encode if only flag)
    
`chmod`
    change permissions
    `666` wr for all
    `755` rwx for owner, rx for group and others
   `777` rwx for all
    
`grep what where.txt`      
   `-Ril` -R recursive, -i ignores case, -l only shows files that match 
   `-E "term1|term2|term3"` will search for all 3 terms
   
`cut`
    `-d '.'` delimiter of fields in this case `.`
    `-f 3-5` cut out all but fields 3,4,5
    
`smbclient`
    lets you access and smb share drive from kali
    for commands see `oscp`
    
`smbmount`
    lets you mount a share on kali
    https://www.techrepublic.com/article/use-smbmount-and-smbclient-to-access-windows-resources-from-linux/
    `smbmount //share_location /mount/point/on/me
    
`sort file.txt | uniq -u`
    -u only displays unique lines
    
`rev`
    reverse each line of input horizontally but keep line order
    vertically
    
`tac`
    will `cat` a file in reverse line order but keeps charater order
    horizontally
    
`strings -n length file.txt`    
    only displays human readable strings of -n length
    
`tr [a-z] [n-za-m]`
    piped input will change letters of first set to match 2nd set (13 places)
    [A-Z] will do the same for capital letters
    
`upx -d` 
    to unpack a upx packed file

`ssh user@ipaddress -p 4434 ls`
    will connect via ssh and run a `ls` cmd on remote

`youtube-dl`
    installed by brew to download youtube videos

`binwalt`
    runs `file` over and over to find nested files
    `-e *` extracts the file and `*` does it to all possiple files
    `-E` checks the entropy of the file. higher the entropy the more
        likly that its encrpted with somthing

`file`    
    get info about a file type
    
CyberChef - https://gchq.github.io/CyberChef/
    easy tool for changing files
    
`tldr`
    gives your cmd examples
    
`\`charater 
    escapes character when put in front of it
    sometimes you need to use absolute path with weird file names like `-`
`./`
    used to run scripts but also will help when access files such as `-`
    tells term to access somthing in current path
    
`find . -size 512c`
    uses find to look for a file that is 512 bytes large
    https://www.tecmint.com/35-practical-examples-of-linux-find-command/
    `find / -type f -size +50M -exec du -h {} \; | sort -n`
        will find files bigger than 50Mbs and sort them
    
`2>/dev/null`
    dumps all errors so they don't see them in the term output
    
`hURL`
    hex, rot13, ect encoder and decoder
    
`mktemp`
    creates a temp file in /etc/tmp/ and returns the path to the file
    `myfile="$(mktemp)"`
    `cd "$(mktemp -d)"`     makes a temp directory
    
`openssl s_client -connect localhost:30001 -ign_eof`
    connect to localhost on port 30001, -ign_eof ignore end of file otherwise
    client will disconnect when it runs out of input
    
`^this^that` 
    in bash, will run perious cmd and sub this for that
    
`ssh user@ip sh`
    will log into user and bypass bash and just give u a shell
    can sub `sh` with any other command you want it to run

`job contorl`
    `&` at the end of a command will run it in the background and display its job
    number
    `Ctrl+z` background and stop a program
    `jobs` show all jobs
    `bg %4` will backgournd job 4 and run it
    `fg %9` will bring job 9 to the fore ground and run

`mktemp -d`
    to make a temp dir or remove -d for file
    
`escape a shell`
    any interactive commands (`pagers, editors, shells, langs`)
    like `more, less, vi,`
    
`ltrace ./an_exicutable`
    runs an_exicutable and prints all dynamic library calls so you can 
    see what the program is doing. things to look for:
        `strcmp` compares strings used for password checking
        `access()` checks permissions based on owner not `whoami`
        `fopen()` opens a file 

`strace`
    shows all the system calls for a program
    
`ss`
    replaces `netstat` (deprocated) with more info
    `-t` tcp ports
    `-u` udp ports
    `-l` listening ports
    `-n` port number
    `-p` process/program name
    
`watch`
    put infront of a cmd to see in real time
    
`tail` 
    to see last 10 lines of a file
    `-f` to see the last 10 lines in real time
`wc`
    to see number of words
    `-l` to see number of lines
`top`
    see processes running by resources usage

#wipe all logs
    `du -h /var/log`    to see size of all log files
    `cat /dev/null > *.log` will empty all logs but keep their filenames

`dmesg`
    see messeges stored in ring buffer (events between boot and startup
    processes)
    `-H` timestamp in nanosec from kernal boot
    `-T` human readable timestamps
    `--follow` watch in realtime
    `dmesg | grep -i "term"` to search for case insensitive search
    
`journalctl`
    read and filter system log messeges
    `-f` follow the journal and see logs as they appear
    `-S "2020-91-12 07:00:00"` see logs SINCE date and time
    `-S -1d` since one day / in the last day
    `-S -1h` since one hour / in the last hour
    `--vacuum-time=1days` removes all logs older than 1 day
    https://www.howtogeek.com/499623/how-to-use-journalctl-to-read-linux-system-logs/
`/var/log` dir for all linux logs

`traceroute`
    check route to a destination
    
`lsof [option] [user name]`
    "list of open file" shows all files that are open by a processes
    `-u darrow` lists all files open by darrow
    `-u ^darrow` list all files open EXCEPT for by darrow
    `-c` list all files open by a process -c processname
    `-p` by process ID
    https://www.geeksforgeeks.org/lsof-command-in-linux-with-examples/
    
`chroot`
    change the root dir for testing or password recovery or new bootloader
    
#editing /etc/interfaces
    https://www.cyberciti.biz/faq/setting-up-an-network-interfaces-file/
    iface eth0 inet static
    address 192.168.1.5
    netmask 255.255.255.0
    gateway 192.168.1.254
    
    auto eth0
    iface eth0 inet dhcp
    
`ifconfig`
    check network interfaces
    `eth0 192.168.x.x` sets the eth0 interface to a static ip


    

    
    
    
    
    
