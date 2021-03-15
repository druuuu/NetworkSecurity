// Golang program to show how
// to use command-line arguments
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	var iface, fileName, pattern string

	var actualBpfFilter string
	// fmt.Println(reflect.ValueOf(os.Args).Kind())

	for i, v := range os.Args {
		if v == "-i" {
			iface = os.Args[i+1]
			fmt.Println("Interface specified by user: ", iface)
		} else if v == "-r" && iface == "" {
			fileName = os.Args[i+1]
			fmt.Println("FileName to read packets from: ", fileName)
		} else if v == "-s" {
			pattern = os.Args[i+1]
			fmt.Println("Pattern specified by user: ", pattern)
		}
		else if i==0 && os.Args[i] != "-r" && os.Args[i] != "-i" && os.Args[i] != "-s" {
			actualBpfFilter = os.Args[i]
			fmt.Println("BPF filter specified by user: ", actualBpfFilter)
		}
		else if i > 0 && os.Args[i-1] != "-r" && os.Args[i-1] != "-i" && os.Args[i-1] != "-s" {
			actualBpfFilter = os.Args[i]
			fmt.Println("BPF filter specified by user: ", actualBpfFilter)
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

	if fileName != "" {
		fmt.Println("Opening file: ", fileName)
		handle, err = pcap.OpenOffline(fileName)
	} else {
		fmt.Println("Opening live connection on interface: ", currDevice.Name)
		handle, err = pcap.OpenLive(currDevice.Name, 1024, true, 30)
	}

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	// handle.SetBPFFilter(pattern)
	handle.SetBPFFilter(actualBpfFilter)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			if (pattern=="") {
				generateOutputForPacket(packet)
			}
			else if (strings.Contains(applicationLayer.Payload().String(), pattern)) {
				generateOutputForPacket(packet)
			}
		}
		else {
			generateOutputForPacket(packet)
		}
	}

}

func generateOutputForPacket(packet gopacket.Packet) {

	var timestamp, destIpAddr, protocolType, srcIpAddr string
	var pktLen, srcPort, destPort int
	var record = make([]string, 0)

	fmt.Println()

	timestamp = packet.Metadata().CaptureInfo.Timestamp.String()
	record = append(record, timestamp)
	pktLen = packet.Metadata().CaptureInfo.CaptureLength

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		ethPacket, _ := etherLayer.(*layers.Ethernet)
		srcMacAddr := ethPacket.SrcMAC.String()
		destMacAddr := ethPacket.DstMAC.String()
		etherType := ethPacket.EthernetType

		// Converting etherType from enum to the hex format as required to be printed
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(etherType))
		record = append(record, srcMacAddr, "->", destMacAddr, "type", "0x"+hex.EncodeToString(b))
	}

	record = append(record, "len", strconv.Itoa(pktLen))

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		if strings.Contains(ipPacket.Protocol.String(), "ICMP") {
			protocolType = "ICMP"
		}
		srcIpAddr = ipPacket.SrcIP.String()
		destIpAddr = ipPacket.DstIP.String()
	}

	ipV6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipV6Layer != nil {
		ipPacket, _ := ipV6Layer.(*layers.IPv6)
		srcIpAddr = ipPacket.SrcIP.String()
		destIpAddr = ipPacket.DstIP.String()
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		protocolType = "TCP"
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		srcPort = int(tcpPacket.SrcPort)
		destPort = int(tcpPacket.DstPort)
		record = append(record, srcIpAddr+"."+strconv.Itoa(srcPort), "->", destIpAddr+"."+strconv.Itoa(destPort), protocolType)
		if tcpPacket.FIN {
			record = append(record, "FIN")
		}
		if tcpPacket.SYN {
			record = append(record, "SYN")
		}
		if tcpPacket.RST {
			record = append(record, "RST")
		}
		if tcpPacket.PSH {
			record = append(record, "PSH")
		}
		if tcpPacket.ACK {
			record = append(record, "ACK")
		}
		if tcpPacket.URG {
			record = append(record, "URG")
		}
		if tcpPacket.ECE {
			record = append(record, "ECE")
		}
		if tcpPacket.CWR {
			record = append(record, "CWR")
		}
		if tcpPacket.NS {
			record = append(record, "NS")
		}

		// record = append(record, "TCPOptions")
		// for _, v := range tcpPacket.Options {
		// 	record = append(record, v.OptionType.String(), hex.Dump(v.OptionData))
		// }

	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		protocolType = "UDP"
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort := int(udpPacket.SrcPort)
		destPort := int(udpPacket.DstPort)
		record = append(record, srcIpAddr+"."+strconv.Itoa(srcPort), "->", destIpAddr+"."+strconv.Itoa(destPort), protocolType)
	}

	if protocolType == "ICMP" {
		record = append(record, srcIpAddr, "->", destIpAddr, protocolType)
	}

	if protocolType == "" {
		protocolType = "OTHER"
		record = append(record, srcIpAddr, "->", destIpAddr, protocolType)
	}
	
	fmt.Println(strings.Join(record, " "))

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {	
		fmt.Printf("%s", hex.Dump(applicationLayer.Payload()))
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error during packet analysis:", err)
	}
}
