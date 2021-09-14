package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
)

//Basic port scanner built in Go
// takes flags to indicate information
// FLAGS
// -ip (sets the IP address to scan)
// -port (gives port or port range, format xxx-xxx)
// -proto (Sets either TCP or UDP for proto, default tcp
// -timeout (sets the amount of time to wait for connections in seconds)
// -display (sets whether to display closed ports, default off, flag/ does not need input)

// scanner.go -ip <Target_IP> -port <port | Min-Max> -proto {tcp | udp} -timeout {seconds} -display

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
	timeout, _ := strconv.Atoi(*timeoutPtr)
	local_addr := "10.13.37.5:0"
	curr_addr := "10.13.37.5"
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
	proto := strings.ToLower(*protoPtr)  //convert to lower case to match conn input
	if !isValidIP(net.ParseIP(*IPPtr)) { //check if IP is valud
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
		var results bool = true
		var status string = "open"
		currPort := FinalPortList[i]
		var ip_string string = *IPPtr + ":" + strconv.Itoa(currPort)
		if proto == "tcp" {
			laddr, _ := net.ResolveTCPAddr("tcp4", local_addr)
			tcpAddr, _ := net.ResolveTCPAddr("tcp4", ip_string)
			conn, err := net.DialTCP("tcp", laddr, tcpAddr)
			_ = conn
			if err != nil {
				results = false
				status = "closed"
			} else {
				conn.Close()
			}
			if *displayPtr || results { //bool logic so we only print closed ports if display flag was set.
				fmt.Println("Port:", currPort, " : ", status)
			}
		} else if proto == "udp" {
			//!TODO
			//Add code to collect and interpret ICMP response to UDP packet
			//send several times, add flag for number of repeats

			//set up icmp listener
			icmp_conn, icmp_err := icmp.ListenPacket("ip4:icmp", curr_addr)
			if icmp_err != nil {
				fmt.Println("Houston, we have an error")
			}
			_ = curr_addr
			//start UDP setup
			udpAddr, _ := net.ResolveUDPAddr("udp4", ip_string)
			laddr, _ := net.ResolveUDPAddr("udp4", local_addr)
			conn, _ := net.DialUDP("udp", laddr, udpAddr)
			var msg []byte

			deadline := time.Now().Add(time.Duration(timeout)) //computes timeout time and sets on conn
			conn.SetDeadline(deadline)
			buffer := []byte("Hello")
			_, _ = conn.Write(buffer) //send buffered data

			//listen for ICMP response
			length, srcIP, icmp_err := icmp_conn.ReadFrom(msg)
			if icmp_err != nil {
				log.Println(icmp_err)
				continue
			}
			if length == 0 {
				fmt.Println("No Response")
			} else {
				test := srcIP.String()
				if test == *IPPtr {
					fmt.Println("We got a packet")
					fmt.Println(string(msg))
				}

			}

			conn.Close()
			icmp_conn.Close()
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
