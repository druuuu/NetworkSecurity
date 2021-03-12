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
		generateOutputForPacket(packet)
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

	fmt.Println(strings.Join(record, " "))

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Printf("%s", hex.Dump(applicationLayer.Payload()))
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
