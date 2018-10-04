package main
/**
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
	 1,3 general linux kernel option may helps performance of ip layer/ or directly use BSD!!
 2. code
	 2.1 read configs from file and environment
	 2.2 better Golang coding style

[compile]
 ---------
 to compile the code simply : /usr/bin/go build main.go encryption.go config.go
 */

/**
   structure to store program configs
 */

import (
	"github.com/songgao/water"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

type vpnConfig struct {
	// specifies encryption method to use in encryption packet and decryption
	// allowed values is [xor]
	encryptionMethod string

	// remote host Ip that we send our encrypted packets to
	remoteIp net.IP

	// remote host Port
	remotePort uint16

	// species local Ip that we are waiting to receive packets from remote host
	localIp net.IP

	// local port to receive packets from remote host
	localPort uint16

	// the byte array for xor encrytion
	xorKey []byte
}

const (
	// I use TUN interface, so only plain IP packet,
	// no ethernet header + mtu is set to 1300

	// BUFFERSIZE is size of buffer to receive packets
	BUFFERSIZE = 1500
)

// to execute external ip command (to configure link and address ) it get list
// of command line items to execute
// e.g: when we want to run " /sbin/ip addr show ", its argumenst will be
// ["addr","show"]
// we need this to configure TUN device when we create it,
func runIPCmd(args ...string) {
	cmd := exec.Command("/sbin/ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		log.Fatalln("Error running /sbin/ip:", err)
	}
}

//initialize TUN device (make it and configure it)
func init_tun() *water.Interface {
	iface, err := water.NewTUN("")
	if nil != err {
		log.Fatalln("Failed To Init TUN interface:", err)
	}
	log.Println("Interface Name:", iface.Name())

	//LIMIT MTU of TUN Device. this forces kenel to send 1300 bytes at maximum
	//ref: https://en.wikipedia.org/wiki/Maximum_transmission_unit
	runIPCmd("link", "set", "dev", iface.Name(), "mtu", "1300")

	// MAKE it available to OS
	runIPCmd("link", "set", "dev", iface.Name(), "up")
	return iface
}

//get local packets and encrypt them and send over network
func readFromTUNAndSendToUdp(config *vpnConfig, tun_iface *water.Interface) {
	log.Println("read from tun")
	buf := make([]byte, BUFFERSIZE)
	UDPADD := net.UDPAddr{IP: config.remoteIp, Port: (int)(config.remotePort)}
	var i byte
	var udpconn *net.UDPConn

	//sometimes maybe there is no remote server. because it is reseted or
	// did not have enough time to run. we should try to connect
	// I wrote this bad manner in 5min! I think it may have better
	// implementation. if we failed to connect to remote host we will
	// wait for 10s. and we will try 8 times.
	for i = 0; i < 10; i++ {
		var e error
		log.Println("try to connect to remote machine over UDP")
		udpconn, e = net.DialUDP("udp", nil, &UDPADD)
		if nil != e {
			log.Println("could not start udp connection to remote host", e)
		} else {
			break
		}
		log.Println("sleep for 10 seconds")

		time.Sleep(10)
		if i == 8 {
			log.Fatalf("could not connect to remote server", e)
		}
	}

	// NEVER NEVER forget to close open connections.
	defer udpconn.Close()

	//infite loop to capture and send packets
	for {
		log.Println("try to read from TUN")
		plen, err := tun_iface.Read(buf)
		log.Printf("Somthing read from TUN(len:%s)", plen)
		if nil != err {
			log.Fatalf("problem to read packet from TUN device", err)

		}
		if plen == 0 {
			continue

		} else {
			log.Printf("Recived Packet(len %d) From TUN Dev ", plen)
		}
		encrypted_buf, err := EncryptPacket(buf[:plen], config)
		if nil != err {
			log.Printf("problem to encrypt packet(len %d)", plen)
			continue
		}
		_, err = udpconn.Write(encrypted_buf)
		if nil != err {
			log.Println("problem to send packet to remote host", err)
		} else {
			log.Printf("Send packet over UDP (len %s)", len(encrypted_buf))
		}

	}

}

// heer we do reverse work due to before function. we wait to get a packet from
// remote host and decrypt it and inject it to our network through TUN device
func rcvrFromUdpAndWriteToTUN(config *vpnConfig, tun_iface *water.Interface) {
	addr := net.UDPAddr{
		Port: (int)(config.localPort),
		IP:   config.localIp,
	}

	conn, err := net.ListenUDP("udp", &addr)
	defer conn.Close()

	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}
	buf := make([]byte, BUFFERSIZE)
	for {
		rlen, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			log.Println("Error: ", err)
			continue
		}

		// ReadFromUDP can return 0 bytes on timeout
		if 0 == rlen {
			continue
		}
		if remote.IP.Equal(config.remoteIp) == false {
			log.Println("received packet from not defined remote. ignore it")
			continue
		}
		log.Println("Packet (%s len) Arrived From remote (%s). try to decrypt packet", rlen, remote.IP)
		decrypted_buf, err := DecryptPacket(buf[:rlen], config)
		if nil != err {
			log.Println("Problem in Decryption, ignore it", err)
			continue
		}
		_, err = tun_iface.Write(decrypted_buf)
		if nil != err {
			log.Println("some problem in  writing to TUN device ", err)
		} else {
			log.Println("Successfully have written to TUN device")
		}

	}
}

func main() {
	var config *vpnConfig
	if len(os.Args) == 5 {
		config = ParseConfig()
	} else {
		log.Fatalln("main <remote-ip> <remote-port> <local-ip> <local-port>")
	}
	// init dev
	iftun := init_tun()
	// run read thread (go routine)
	go readFromTUNAndSendToUdp(config, iftun)
	// run write thread (go routine)
	go rcvrFromUdpAndWriteToTUN(config, iftun)

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGTERM)

	<-exitChan

}
