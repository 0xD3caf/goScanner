package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

//Basic port scanner built in Go

//!TODO
//change to CLI form
//allow multiple port scanning
//UDP vs TCP switch
//dump to file option
//add flags for scan types, ie. SYN, ACK, FIN, PSH, URG, RST
//add timeout for scanner

func init() {
	fmt.Println("--Initializing main.go--")
}

func main() {
	//starting up and getting IP and port from user
	fmt.Println("Basic port scanner in Go")
	fmt.Println("")
	fmt.Print("Enter IP to Scan: ")
	var IPstr string
	var portStr string
	proto := "tcp"
	timeout := "10" + "s"
	timeoutDuration, _ := time.ParseDuration(timeout)
	fmt.Scanln(&IPstr)
	userIP := net.ParseIP(IPstr)
	if !isValidIP(userIP) {
		fmt.Println("This IP is not Valid, Please try again")
		os.Exit(3)
	}
	fmt.Print("Please enter the port: ")
	fmt.Scanln(&portStr)
	userPort, _ := strconv.Atoi(portStr)
	if !isValidPort(userPort) {
		fmt.Println("This port is not valid, Please try again")
		os.Exit(3)
	}
	fmt.Println("---------------------------------------------------------")

	//Begin scanning process here

	results := Scanner(IPstr, userPort, proto, timeoutDuration)
	var status string
	if results {
		status = "Open"
	} else {
		status = "Closed"
	}
	fmt.Println("Port:", userPort, " is : ", status)
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
	fmt.Println("--Port Scanner started--")
	addr := fmt.Sprintf(IP+":%d", port)
	conn, err := net.DialTimeout(proto, addr, timeout)
	/*
		fmt.Println("Testing Conn")
		fmt.Println(conn)
		fmt.Println("Testing err")
		fmt.Println(err)
	*/
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
