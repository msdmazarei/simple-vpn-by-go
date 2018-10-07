[General]
---------

this code is implementation of simple VPN protcols which hides traffic from
Man-In-Middle By encrypting Packets. this is done cause of requested task ref:
https://github.com/mysteriumnetwork/winter-is-coming/blob/master/quests/Secret_Whispering.md
this implmentation idea is very simple and this code is very dummy(because I did
it when I was deploying and maitaing my production servers) and I will
mention how could we promote it.
to hide packets from (white walkers!) we should encrypt all network traffic which
they could sniff. we could handle this by [TUN/TAP](https://en.wikipedia.org/wiki/TUN/TAP)
that provides virtual interface to user-space program,
there is another way that could helps us is using iptables ( by REDIRECT and
write our app by [RAW_SOCKET](http://man7.org/linux/man-pages/man7/raw.7.html))
or write custom Linux driver for network and at worse case scenario (by passing
linux kernel network stack) we could handle traffic manually( by [DPDK](  https://www.dpdk.org/).  the final solution depends on many
situations and if we had no high traffic we could use iptables (simpler and
slower ) or TUN/TAP (intermediate) but for high traffic(I mean more than 5Gbps)
probebly we should bypass kernel!

[what does this code do?]
-------------------------
this project contains below files:
 1. config.go (that should retreive configs from file and env)
 2. encryption.go (that encrypts/decrypts byte array)
 3. main.go (that inits TUN device and capture packets then sends them over network to target machine)


[flow:]
-------

 1. parse config (by calling ParseConfig)
 2. init TUN device and configure it and make it up (user should set address and define routes manually to his device)
 3. start a thread (go routine) to capture packets from TUN device and try to encrypt and to send them to target machine over network using UDP protocol.
 4. start a thead (go routine) to listen to network and receive packets and try to decrypt and push them to TUN device.
[why TUN device is better than TAP for this code?]
--------------------------------------------------

 as far as I know TUN device packets pass through linux routing, so already it could handle routing and many unnessecry challenges, but TAP is a layer 2 device and if I used it may force me to handle parse ethernet frame and routing mannually!

[Improvment]
------------

 1. Performance
 
	 1.1 it is better to use [SO_REUSEPORT]([https://lwn.net/Articles/542629/]) option for UDP sockets(becuase it allows to multiple thread/process to listen on same port) .
	 
	 1.2 it is better to run multiple thread(go routine) to increase capture and transfer performance
	 
	 1.3 general linux kernel option may helps performance of ip layer/ or 
	 directly use BSD!!
 
 2. code

	 2.1 read configs from file and environment

	 2.2 better Golang coding style

[compile]
 ---------
 to compile the code simply : 
 
 /usr/bin/go *go
