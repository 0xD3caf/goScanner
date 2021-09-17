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
	"golang.org/x/net/ipv4"
)

/************************************************
*                                               *
*       UDP SCANNING REQUIRES ROOT PRIV         *
*                                               *
*************************************************


//Basic port scanner built in Go
// takes flags to indicate information
// FLAGS
// -ip (sets the IP address to scan)
// -port (gives port or port range, format xxx-xxx)
// -proto (Sets either TCP or UDP for proto, default tcp
// -timeout (sets the amount of time to wait for connections in seconds)
// -display (sets whether to display closed ports, default off, flag/ does not need input)
// -retry (sets number of attempts per port for UDP scanning)

// scanner.go -ip <Target_IP> -port <port | Min-Max> -proto {tcp | udp} -timeout {seconds} -display

//!TODO
//dump to file option
//add scan type ICMP
//add flags for scan types, ie. SYN, ACK, FIN, PSH, URG, RST
//add real UDP scanning
// -outfile (optional dump to file)
//-help (helpfile)
//ABILITY TO RANDOMIZE SOURCE PORT

//Update UDP scanning, again. Might try libpcap to collect ICMP response
//first step is to capture controlled pings

*/
func main() {

	//LOCAL ADDRESS TO SCAN FROM (HOST:PORT)
	local_addr := "10.13.37.6:45555"

	//starting up and getting flag values
	IPPtr := flag.String("ip", "Localhost", "IP Selection")
	portPtr := flag.String("port", "0", "Port or port range to scan")
	protoPtr := flag.String("proto", "tcp", "Select either UDP or TCP scanning")
	timeoutPtr := flag.String("timeout", "10", "Set amount of time before timing out connection")
	displayPtr := flag.Bool("display", false, "Sets whether to display closed ports")
	retryPtr := flag.String("retry", "5", "retry attempts for UDP scanning")

	flag.Parse()
	if !isValidIP(net.ParseIP(*IPPtr)) { //check if IP is valud
		fmt.Println("This IP is not Valid, Please try again")
		os.Exit(3)
	}
	timeout, _ := strconv.Atoi(*timeoutPtr)
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
	proto := strings.ToLower(*protoPtr) //convert to lower case to match conn input

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
			ip_str := strings.Split(local_addr, ":")[0]
			icmp_conn, icmp_err := icmp.ListenPacket("ip4:icmp", ip_str)
			if icmp_err != nil {
				fmt.Println("Houston, we have an error")
				fmt.Println(icmp_err)
			}
			var msg []byte

			//start UDP setup
			udpAddr, err := net.ResolveUDPAddr("udp4", ip_string)
			handle_err(err)
			laddr, err := net.ResolveUDPAddr("udp4", local_addr)
			handle_err(err)
			conn, err := net.DialUDP("udp", laddr, udpAddr)
			handle_err(err)
			icmp_conn.SetDeadline(time.Now().Add(1 * time.Second)) //sets wait time

			deadline := time.Now().Add(time.Duration(timeout)) //computes timeout time and sets on conn
			err = conn.SetDeadline(deadline)
			handle_err(err)
			buffer := []byte("Hello")
			max := *retryPtr
			int_max, _ := strconv.Atoi(max)

			var timeout, icmp_rtrn_3, icmp_rtrn_other bool = false, false, false
			_, _ = icmp_rtrn_3, icmp_rtrn_other
			for j := 0; j < int_max; j++ {
				_, _ = conn.Write(buffer) //send buffered data

				//ICMP_test_rtrn_3(ip_str) //TESTING FUNCTION
				length, srcIP, icmp_err := icmp_conn.ReadFrom(msg)
				_, _ = length, srcIP
				if icmp_err != nil {
					err_string := icmp_err.Error()
					if strings.Contains(err_string, "i/o timeout") {
						timeout = true
					}
					//need to swap in icmp collect here so it can run multiple times
					//add some vars to store and use them instead to check later

					//need to generate icmp echo reply packets for testing ??
				}
			}
			if timeout {
				fmt.Println("port:", currPort, " Open | Filtered")
			} else if icmp_rtrn_3 {
				fmt.Println("port:", currPort, " Open")
			} else if icmp_rtrn_other {
				fmt.Println("port:", currPort, " Filtered")
			}
			//listen for ICMP response
			//no icmp packet means no reponse and port

			/*
				if icmp_err != nil {
					err_string := icmp_err.Error()
					if strings.Contains(err_string, "i/o timeout") {
						fmt.Println("Open |  Filtered")
					}
				}
				if srcIP != nil {
					test := srcIP.String()
					if test == *IPPtr {
						fmt.Println("Port: ", currPort, " Status: Closed")
					} else if length == 0 && srcIP == nil {
						fmt.Println("port:", currPort, " Status: Open")
					} else {
						fmt.Println("where did this come from")
					}
				}*/
			conn.Close()
			icmp_conn.Close()
		}
	}
}

func isValidIP(IP net.IP) bool {
	//IP Check function, returns false is not valid IP
	return IP.To4() != nil
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

func handle_err(x error) {
	if x != nil {
		log.Fatal(x)
		os.Exit(3)
	}
}

func ICMP_test_rtrn_3(addr string) {
	//tests returning ICMP error 3'
	conn, _ := icmp.ListenPacket("ip4:icmp", "127.0.0.1")
	defer conn.Close()
	target_ip, err := net.ResolveIPAddr("ip4", addr)
	handle_err(err)
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 3,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1, //<< uint(seq), // TODO
			Data: []byte(""),
		},
	}
	bytes, err := m.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.WriteTo(bytes, target_ip)
	if err != nil {
		log.Fatal(err)
	}
}
func ICMP_test_rtrn_other() {
	// tests returning ICMP error of any type other than 3
}
