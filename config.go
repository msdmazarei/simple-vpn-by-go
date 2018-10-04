package main

import (
	"log"
	"net"
	"os"
	"strconv"
)

//very simple and bad format of config parser, its better to use
// golang default config parsers like go-ini, go-config ....

func ParseConfig() *vpnConfig {
	config := new(vpnConfig)

	RemoteIp := os.Args[1]
	RemotePort :=os.Args[2]
	LocalIp := os.Args[3]
	LocalPort :=os.Args[4]

	remoteIp := net.ParseIP(RemoteIp)
	if remoteIp==nil {
		log.Fatalln("your remote ip is not valid ipv4")
	}
	remotePort,e :=strconv.Atoi(RemotePort)
	if e!=nil {
		log.Fatalln("your port is not valid port")
	}


	localIp := net.ParseIP(LocalIp)
	if localIp==nil {
		log.Fatalln("your local ip is not valid ipv4")
	}
	localPort,e :=strconv.Atoi(LocalPort)
	if e!=nil {
		log.Fatalln("your local port is not valid port")
	}

	config.remoteIp = remoteIp
	config.remotePort=((uint16)(remotePort))

	config.localIp = localIp
	config.localPort=((uint16)(localPort))
	log.Printf("Ip to Connect: %s Port:%s",RemoteIp,RemotePort)
	config.xorKey=[]byte{1,2,3,4,5,6,7,8,9,10,11,12}
	config.encryptionMethod = "xor"
	return config
}


