# Simple-VPN-With-TLS
A very simple (and buggy) VPN program that uses TLS over a TCPtunnel

## IP Assumptions
* Server Nat Network Address:     10.0.2.4
* Server bridged adapter:         10.0.1.156
* Client Nat Network address:     10.0.2.5
* Host V bridged address:         10.0.1.26
* Apache webserver installed and running on Host V


## Instructions

1. Set up Three virtual machines using http://jupiter.syr.edu/seed/images/16_04_v4/SEEDUbuntu-16.04-32bit.zip
2. Server should be set up with nat network on adapter 1 using http://www.cis.syr.edu/~wedu/seed/Documentation/VirtualBox/VirtualBox_NATNetwork.pdf
3. Sever  network adapter 2 should be placed in bridged mode
4. Clone server and rename to Client, network adapter should be nat network following the PDF above
5. Clone server and rename to Host V, set network adapter to bridged mode
6. Start all the virtual machines up
7. On each machine in type git clone https://github.com/ckchessmaster/Simple-VPN-With-TLS.git
    * cd Simple-VPN-With-TLS
    * type make clean
    * type make install
8. From here on out operate all commands in the  Simple-VPN-With-TLS directory of each machine

### NOTE If your addresses differ from the assumptions after running ifconfig -a, match the assumptions and replace in next steps

## for non-Encrypted connection follow steps 9-14
## for help using vpnClient or vpnServer use : sudo ./vpnServer -h  or sudo ./vpnClient -h

9.  On Server:  sudo ./vpnServer -d  (the -d will debug to command line)
10. On Client:  sudo ./vpnClient -i 10.0.2.4 (-i tells client what ip server is at)
              * sudo ifconfig tun0 10.4.2.97/24 up
              * sudo route add -net 10.4.2.0/24 tun0
              * sudo route add -net 10.0.1.0/24 tun0
11. On Server:  sudo sysctl -w net.ipv4.ip_forward=1
              * sudo ifconfig tun0 10.4.2.5/24 up
              * sudo route add -net 10.4.2.0/24 tun0
12. On Host V   sudo route add -net 10.4.2.0/24 gw 10.0.156 enp0s3
13. On Client   Open wireshark and monitor enp0s3
14. On Client   open firefox browse to 10.0.1.26 (host V)
                * you should see traffic from the host website in plain text
![Alt text](/pthml.JPG?raw=true "Results from Client clear Host V")

## for Encrypted connection follow steps 15-XX
15. On Server: cd /cert
* type sudo ./generateCerts.sh
* enter in the information for your server first, then your client.
* make sure you put your IP address under common name of the appropriate machine
* complete this on server and client machines
![Alt text](/certs.JPG?raw=true "Creating the certs")
16. On Client   scp -r seed@10.0.2.4:/home/seed/Simple-VPN-With-TLS/cert /home/seed/Simple-VPN-With-TLS/
18. On Server:  sudo ./vpnServer -d -e
19. On Client:  sudo ./vpnClient -e -d -i 10.0.2.4
              * sudo ifconfig tun0 10.4.2.97/24 up
              * sudo route add -net 10.4.2.0/24 tun0
              * sudo route add -net 10.0.1.0/24 tun0
20. On Server:  sudo sysctl -w net.ipv4.ip_forward=1
              * sudo ifconfig tun0 10.4.2.5/24 up
              * sudo route add -net 10.4.2.0/24 tun0
21. On Host V   sudo route add -net 10.4.2.0/24 gw 10.0.156 enp0s3
22. On Client   Open wireshark and monitor enp0s3
22. On Client   open firefox browse to  10.0.1.26 (host V)
23. You will notice if you right click on a packet and go to follow the TCP stream it will be unreadable
![Alt text](/encryptedhtml.JPG?raw=true "Encrypted html")
