package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

//Basic port scanner built in Go
// takes flags to indicate information
// FLAGS
// -IP (sets the IP address to scan)
// -port (gives port or port range, format xxx-xxx)
// -proto (Sets either TCP or UDP for proto, default tcp
// -timeout (sets the amount of time to wait for connections in seconds)
// -display (sets whether to display closed ports, takes bool, default false/off)

//!TODO
//dump to file option
//add flags for scan types, ie. SYN, ACK, FIN, PSH, URG, RST
//ad real UDP scanning
// -outfile (optional dump to file)

func main() {
	//starting up and getting IP and port from user
	IPPtr := flag.String("IP", "Localhost", "IP Selection")
	portPtr := flag.String("port", "0", "Port or port range to scan")
	protoPtr := flag.String("proto", "tcp", "Select either UDP or TCP scanning")
	timeoutPtr := flag.String("timeout", "10", "Set amount of time before timing out connection")
	displayPtr := flag.Bool("display", false, "Sets whether to display closed ports")

	flag.Parse()
	timeout := *timeoutPtr + "s"
	var port int
	FinalPortList := make([]int, 0)
	if strings.Contains(*portPtr, "-") {
		portsList := strings.Split(*portPtr, "-")
		maxval, _ := strconv.Atoi(portsList[1])
		for minval, _ := strconv.Atoi(portsList[0]); minval <= maxval; minval++ {
			FinalPortList = append(FinalPortList, minval)
		}
	} else {
		port, _ = strconv.Atoi(*portPtr)
		FinalPortList = append(FinalPortList, port)
	}
	/*
		fmt.Printf("IP is: %s\n", *IPPtr)
		fmt.Printf("Port is: %d\n", *portPtr)
		fmt.Printf("Proto is: %s\n", *protoPtr)
		fmt.Printf("Timeout is: %s\n", timeout)
	*/
	proto := strings.ToLower(*protoPtr)
	timeoutDuration, _ := time.ParseDuration(timeout)
	if !isValidIP(net.ParseIP(*IPPtr)) {
		fmt.Println("This IP is not Valid, Please try again")
		os.Exit(3)
	}
	//needs check for every object in range
	for i := 0; i < len(FinalPortList); i++ {
		if !isValidPort(FinalPortList[i]) {
			fmt.Println("This port is not valid, Please try again")
			os.Exit(3)
		}
	}
	fmt.Println("---------------------------------------------------------")

	//Begin scanning process here
	for i := 0; i < len(FinalPortList); i++ {
		var status string
		currPort := FinalPortList[i]
		results := Scanner(*IPPtr, currPort, proto, timeoutDuration)
		if results {
			status = "Open"
		} else {
			status = "Closed"
		}
		if *displayPtr || results {
			fmt.Println("Port:", currPort, " : ", status)
		}
	}
}

func isValidIP(IP net.IP) bool {
	if IP.To4() != nil {
		return true
	}
	return false
}

func isValidPort(port int) bool {
	x := 0
	y := 65535
	if x <= port && port <= y {
		return true
	}
	return false
}

func Scanner(IP string, port int, proto string, timeout time.Duration) bool {
	addr := fmt.Sprintf(IP+":%d", port)
	conn, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
