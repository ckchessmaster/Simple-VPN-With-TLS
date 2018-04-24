# Simple-VPN-With-TLS
A very simple (and buggy) VPN program that uses TLS over a TCPtunnel

## IP Assumptions
Server Nat Network Address:     10.0.2.4
Server bridged adapter:         10.0.1.156
Client Nat Network address:     10.0.2.5
Host V bridged address:         10.0.1.26

## Instructions

1. Set up Three virtual machines using http://jupiter.syr.edu/seed/images/16_04_v4/SEEDUbuntu-16.04-32bit.zip
2. Server should be set up with nat network on adapter 1 using http://www.cis.syr.edu/~wedu/seed/Documentation/VirtualBox/VirtualBox_NATNetwork.pdf
3. Sever  network adapter 2 should be placed in bridged mode
4. Clone server and rename to Client, network adapter should be nat network following the PDF above
5. Clone server and rename to Host V, set network adapter to bridged mode
6. Start all the virtual machines up
7. On each machine in type git clone https://github.com/ckchessmaster/Simple-VPN-With-TLS.git
    cd Simple-VPN-With-TLS
    type make clean
    type make install
8. From here on out operate all commands in the  Simple-VPN-With-TLS directory of each machine

### NOTE If your addresses differ from the assumptions after running ifconfig -a, mtach the assumptions and replace in next steps

9. On Server:   sudo ./vpnServer -d  (the -d will debug to command line)
10. on Client:  sudo ./vpnClient -i 10.0.2.4
                sudo ifconfig tun0 10.4.2.97/24 up
                sudo route add -net 10.4.2.0/24 tun0
                sudo route add -net 10.0.1.0/24 tun0
11. on Server:  sudo sysctl -w net.ipv4.ip_forward=1
                sudo ifconfig tun0 10.4.2.5/24 up
                sudo route add -net 10.4.2.0/24 tun0
12. on Host V   sudo route add -net 10.4.2.0/24 gw 10.0.156 enp0s3
13. on Client   ping 10.0.1.26 (host V)
14. on Host V   open wireshark and monitor enp0s3, you should see traffic from the clients tun0 (10.4.2.97)
![Alt text](/hostVping.JPG?raw=true "Results from Client tunnel to Host V")
