# network NameSpace - Aware TCP Redirector
This program is a Proof-of-Concept for a TCP redirector that can receive and emit TCP connections in different Linux network namespaces.

-----------------------
# Compilation / installation
The program is so tiny and self-contained, you can install it with only :
```
gcc -o nsar nsar.c 
sudo mv nsar /usr/local/bin
sudo setcap cap_sys_admin+ep /usr/local/bin/nsar
```

-----------------------
# Use cases
- Injecting supervision or administration traffic into VRF/private L3 without interfering with addressing plan
- Consolidate incoming connections from many internet access, each one in a different namespace, into a unique server like SMTP, SSH, HTTPS, RDP...
- Maintaining local X11 when using a VPN in a Namespace, for example when playing Hack-the-box

-----------------------
# Ideas for the future
- Making logs
- Having a dynamic configuration handling multiple redirector
- Rules to route traffic upon source addresse and local incoming socket, to different destinations
- Using "IP Any" from Linux kernel to implement IPv6 -> IPv4+VRF translation or NAT64/DNS64- 


-----------------------
# Licence
This program is released under the terms of the GNU GPLv3 License.
It comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain conditions.
See LICENSE.txt file


