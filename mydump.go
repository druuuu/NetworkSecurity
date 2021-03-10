// Golang program to show how
// to use command-line arguments
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	var iface string
	var fileName string
	var bpfFilter string

	// fmt.Println(reflect.ValueOf(os.Args).Kind())

	for i, v := range os.Args {
		if v == "-i" {
			iface = os.Args[i+1]
			fmt.Println("Interface: ", iface)
		} else if v == "-r" && iface == "" {
			fileName = os.Args[i+1]
			fmt.Println("FileName: ", fileName)
		} else if v == "-s" {
			bpfFilter = os.Args[i+1]
			fmt.Println("BPF filter specified: ", bpfFilter)
		}
	}

	// get all interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var currDevice pcap.Interface
	var handle *pcap.Handle

	// Print device information
	fmt.Println("Devices found:")
	for _, device := range devices {

		if iface == "" {
			currDevice = device
			break
		}
		if iface == device.Name {
			currDevice = device
			break
		}

	}

	// Open device
	// handle, err = pcap.OpenLive(currDevice.Name, snapshot_len, promiscuous, timeout)
	handle, err = pcap.OpenLive(currDevice.Name, 50, false, 1000)

	fmt.Println("Interface handle opened")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("Setting BPF Filter")
	handle.SetBPFFilter(bpfFilter)

	fmt.Println("Starting packet capture")
	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
	}

}
