#log into server with no password

#create ssh key inside ~/.ssh
    ssh-keygen -t rsa -b 4096
    
#copy key to the server
    ssh-copy-id -i ~/.ssh/<ssh key> <user>@<server ip>
#you will need your username and password already made on the server
#connect to the server with the key to confirm
    ssh <user>@<server ip> -i ~/.ssh/<ssh key>
    
----------------------------------------------------------------------
~/.ssh/config for shortcuts
----------------------------------------------------------------------



----------------------------------------------------------------------
kill hung ssh connection    
----------------------------------------------------------------------
# find the connection   
    # linux
    `netstat -antp`
    
    # mac
    FLAG

#look for the PID and kill it
    `kill <PID>`


----------------------------------------------------------------------
scp
----------------------------------------------------------------------
# push - from host to remote
    scp [cert] file host:path
    `scp -i ~/.ssh/my_cert user@10.0.0.9:/home/user/`


# pull - from remote host to me
    scp [cert] host:file path

----------------------------------------------------------------------
SOCKS5 proxy and firefox thru ssh
----------------------------------------------------------------------
# install `foxyproxy` in firefox and configure:
    * proxy type: SOCKS5
    * proxy ip: 172.0.0.1
    * port: 7000
    * no username or password
# connect to the client you want to use the webrowser on
    `ssh <user>@<ip> -L <fwd port on my mechine>:127.0.0.1:<port from ip> -D 7000`
    https://explainshell.com/explain?cmd=ssh+user%4010.0.10.25+-L+9999%3A127.0.0.1%3A6667+-D+7000    
    
# example `ssh ubuntu@100.112.254.77 -L 9999:127.0.0.1:6667 -D 7000`
    so `6667` on `100.112.254.77` will be forwarded to my port `9999` 
    and i can interact with the tunnel with my port `7000`

----------------------------------------------------------------------
Proxychains4 with socks5 tunnels
----------------------------------------------------------------------
`proxychains4 <cmd>`
    *will tell you if its working:
    proxychains] Strict chain  ...  127.0.0.1:7000  ...  10.0.60.77:22  ...  OK
    [proxychains] Strict chain  ...  127.0.0.1:7000 [proxychains] Strict chain
    ...  127.0.0.1:7000 [proxychains] Strict chain 
    
----------------------------------------------------------------------
Port forwarding via ssh
----------------------------------------------------------------------
`-D` 

`-L`

`-R`
