// Golang program to show how
// to use command-line arguments
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
			// TODO: Change to incorporate read from file
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
	handle, err = pcap.OpenLive(currDevice.Name, 1024, false, 30)

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
		//fmt.Println(packet)
		fmt.Println("______ANOTHER PACKET!______")
		printPacketInfo(packet)
	}

}

func printPacketInfo(packet gopacket.Packet) {

	fmt.Println("Printing packet info::")

	// var timestamp string
	// var srcMacAddr, destMacAddr, etherType, srcIpAddr, destIpAddr, protocolType //string
	var destIpAddr, protocolType, srcIpAddr string
	var pktLen, srcPort, destPort int
	// var tcpFlags []string
	var record = make([]string, 15)

	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		// fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		fmt.Println(reflect.ValueOf(ethernetPacket.SrcMAC).Kind())

		srcMacAddr := ethernetPacket.SrcMAC
		destMacAddr := ethernetPacket.DstMAC
		etherType := ethernetPacket.EthernetType

		record = append(record, string(srcMacAddr), "->", string(destMacAddr), "type", string(etherType))
	}

	app := packet.ApplicationLayer()
	payload := app.Payload()
	pktLen = len(payload)

	record = append(record, "len", string(pktLen))

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")

		ip, _ := ipLayer.(*layers.IPv4)
		// fmt.Println(ip)
		// fmt.Println(ip.Protocol)

		srcIpAddr = string(ip.SrcIP)
		destIpAddr = string(ip.DstIP)
		// pktLen := ip.Length

		// append(record, string(srcIpAddr), string(destIpAddr))

		// fmt.Println("!!!ip.Length: ", pktLen)

		if strings.Contains(string(ip.Protocol), "ICMP") {
			fmt.Println("Protocol: ", ip.Protocol)
			protocolType = "ICMP"
		}
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		srcPort = int(tcp.SrcPort)
		destPort = int(tcp.DstPort)
		protocolType = "TCP"

		record = append(record, srcIpAddr+"."+string(srcPort), "->", destIpAddr+"."+string(destPort))
		record = append(record, protocolType)
		// TODO: Add more of these
		if tcp.SYN {
			// tcpFlags[0] = "SYN"
			record = append(record, "SYN")
		}
		if tcp.ACK {
			// tcpFlags[1] = "ACK"
			record = append(record, "ACK")
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)

		srcPort := int(udp.SrcPort)
		destPort := int(udp.DstPort)
		protocolType = "UDP"
		record = append(record, srcIpAddr+"."+string(srcPort), "->", destIpAddr+"."+string(destPort))
		record = append(record, protocolType)

		// udp.Payload
	}

	if protocolType == "ICMP" {
		record = append(record, protocolType)
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	fmt.Println()
	fmt.Println()

	fmt.Println("Printing record:")
	fmt.Println(strings.Join(record, " "))

	// fmt.Print(srcMacAddr + " -> " + destMacAddr + " type " + etherType + " len " + strconv.Itoa(pktLen) + " " + srcIpAddr + "." + strconv.Itoa(srcPort) + " -> " + destIpAddr + "." + strconv.Itoa(destPort) + " " + protocolType + " " + strings.Join(tcpFlags, " "))

	/*// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}*/

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
