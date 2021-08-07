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
// -ip (sets the IP address to scan)
// -port (gives port or port range, format xxx-xxx)
// -proto (Sets either TCP or UDP for proto, default tcp
// -timeout (sets the amount of time to wait for connections in seconds)
// -display (sets whether to display closed ports, default off, flag/ does not need input)

// scanner.go -ip <Target_IP> -port <port | Min-Max> -proto {tcp | udp} -timeout {Seconds} -display (shows_closed_ports)

//!TODO
//dump to file option
//add scan type ICMP
//add flags for scan types, ie. SYN, ACK, FIN, PSH, URG, RST
//add real UDP scanning
// -outfile (optional dump to file)
//-help (helpfile)

func main() {
	//starting up and getting flag values
	IPPtr := flag.String("ip", "Localhost", "IP Selection")
	portPtr := flag.String("port", "0", "Port or port range to scan")
	protoPtr := flag.String("proto", "tcp", "Select either UDP or TCP scanning")
	timeoutPtr := flag.String("timeout", "10", "Set amount of time before timing out connection")
	displayPtr := flag.Bool("display", false, "Sets whether to display closed ports")

	flag.Parse()
	timeout := *timeoutPtr + "s" //add time value to timeout so it can be interpreted
	var port int
	FinalPortList := make([]int, 0)
	if strings.Contains(*portPtr, "-") {
		portsList := strings.Split(*portPtr, "-") //if a - was present, split to get min+max
		maxval, _ := strconv.Atoi(portsList[1])
		for minval, _ := strconv.Atoi(portsList[0]); minval <= maxval; minval++ { //loop through from minval to maxval and add that value to ports list
			FinalPortList = append(FinalPortList, minval) //end with list of all ports in range to scan
		}
	} else {
		port, _ = strconv.Atoi(*portPtr) //if it was single port, we just append to list
		FinalPortList = append(FinalPortList, port)
	}
	/*
		fmt.Printf("IP is: %s\n", *IPPtr)
		fmt.Printf("Port is: %d\n", *portPtr)
		fmt.Printf("Proto is: %s\n", *protoPtr)
		fmt.Printf("Timeout is: %s\n", timeout)
	*/
	proto := strings.ToLower(*protoPtr)               //convert to lower case to match conn input
	timeoutDuration, _ := time.ParseDuration(timeout) //convert time string to time object
	if !isValidIP(net.ParseIP(*IPPtr)) {              //check if IP is valud
		fmt.Println("This IP is not Valid, Please try again")
		os.Exit(3)
	}
	//needs check for every object in range
	for i := 0; i < len(FinalPortList); i++ { //loop through all ports checking if valid
		if !isValidPort(FinalPortList[i]) {
			fmt.Println("This port is not valid, Please try again")
			os.Exit(3)
		}
	}
	fmt.Println("---------------------------------------------------------")

	//Begin scanning process here
	for i := 0; i < len(FinalPortList); i++ { //loops though all ports in port list
		var status string
		currPort := FinalPortList[i]
		results := Scanner(*IPPtr, currPort, proto, timeoutDuration) //calls scanner to check port
		if results {
			status = "Open"
		} else {
			status = "Closed"
		}
		if *displayPtr || results { //bool logic so we only print closed ports if display flag was set.
			fmt.Println("Port:", currPort, " : ", status)
		}
	}
}

func isValidIP(IP net.IP) bool {
	//IP Check function, returns false is not valid IP
	if IP.To4() != nil {
		return true
	}
	return false
}

func isValidPort(port int) bool {
	//port check function, returns false if port is not valid
	x := 0
	y := 65535
	if x <= port && port <= y {
		return true
	}
	return false
}

func Scanner(IP string, port int, proto string, timeout time.Duration) bool {
	//scanning function, takes inputs, opens connection and checks for error
	//if no error connection was made and port is open
	addr := fmt.Sprintf(IP+":%d", port)
	conn, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		return false
	}
	conn.Close() //closes connecton
	return true
}
