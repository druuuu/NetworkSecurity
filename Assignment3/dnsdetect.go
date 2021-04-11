package main

import (
	"fmt" //for loggin errors
	"log"
	"os"
	"time"
	"strconv"
	"github.com/google/gopacket" //for gopacket
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap" //for pcap
)

func getTargetInterface(inputInt string) string {
	devices, _ := pcap.FindAllDevs()
	nDevices := len(devices)
	var availableDevices = make([]string, nDevices, nDevices)

	inputIntAvailable := false

	for i, device := range devices {
		// fmt.Println("FullDevice", device, " Name: ", device.Name)
		availableDevices[i] = device.Name

		if device.Name == inputInt {
			inputIntAvailable = true
		}
	}

	if inputInt != "" && !inputIntAvailable {
		fmt.Println("Invalid interface provided. Please use one of", availableDevices)
		os.Exit(1)
	}

	if inputIntAvailable {
		return inputInt
	}

	fmt.Println("Using default interface", availableDevices[0])
	return availableDevices[0]
}

func getEthernetTypeHex(ethernetType string) string {
	var m = map[string]string{
		"ARP":                "0x0806",
		"CiscoDiscovery":     "0x2000",
		"Dot1Q":              "0x8100",
		"EAPOL":              "0x888e",
		"ERSPAN":             "0x88be",
		"EthernetCTP":        "0x9000",
		"IPv4":               "0x0800",
		"IPv6":               "0x86DD",
		"LLC":                "0",
		"LinkLayerDiscovery": "0x88cc",
		"MPLSMulticast":      "0x8848",
		"MPLSUnicast":        "0x8847",
		"NortelDiscovery":    "0x01a2",
		"PPP":                "0x880b",
		"PPPoEDiscovery":     "0x8863",
		"PPPoESession":       "0x8864",
		// "Dot1Q":                       "0x88a8",
		"TransparentEthernetBridging": "0x6558",
	}
	return m[ethernetType]
}

type DNSQuestion struct {
	uniqueID int // DNSID of the question or answer
}

type DNSCounts struct {
	qCount int // number of questions sent
	aCount int // number of answers received
	aIPs [][]string
	qTime time.Time
}

/**
* Keep a map of DNSQuestion(uniqueID - dnsID) to DNSCounts(qCount - number of questions sent, aCount - number of answers received)
* If you receive an answer for which there's not DNSQuestion present then HACKED
* If count of answers till now > count of questions till now then HACKED
**/
var questionToAnswerMap map[DNSQuestion]DNSCounts

const MAX_SECONDS_ELAPSED = 60

func analyzePacket(packet gopacket.Packet) {

	fmt.Println()
	fmt.Println("======== New Packet =========")
	packetTime := packet.Metadata().Timestamp

	var dnsID uint16
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		dnsID = dns.ID

		isAnswer := (dns.ANCount > 0)

		if isAnswer {
			fmt.Println("ANSWER PACKET")
		} else {
			fmt.Println("QUESTION PACKET")
		}

		for _, dnsQuestion := range dns.Questions {
			dnsQuestionTypeStr := ""
			if dnsQuestion.Type.String() == "A" {
				dnsQuestionTypeStr = "IPv4 DNS Question"
			} else if dnsQuestion.Type.String() == "AAAA" {
				dnsQuestionTypeStr = "IPv6 DNS Question"
			}
			fmt.Println("dnsQuestionTypeStr: ", dnsQuestionTypeStr)
			fmt.Println("dnsQuestion.Name: ", dnsQuestion.Name)
			// fmt.Println("DNSQuestionName:", string(dnsQuestion.Name), "DNSQuestionType:", dnsQuestion.Type.String(), "-", dnsQuestionTypeStr)

			// isQuestion
			if !isAnswer {

				// fmt.Println("!!!!!!!!isQuestion")
				if _, contains := questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}]; contains {
					dnsCounts := questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}]
					dnsCounts.qCount += 1
					questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}] = dnsCounts
				} else {
					questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}] = DNSCounts{qCount: 1, aCount: 0, qTime: packetTime, aIPs: make([][]string, 0)}
				}

			} else {

				// fmt.Println("!!!!!!!!isAnswer")
				if _, contains := questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}]; contains {
					// fmt.Println("MAP CONTAINS ANSWERR")
					dnsCounts := questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}]
					dnsCounts.aCount += 1
					ips := make([]string, 1)

					for _, dnsAnswer := range dns.Answers {
						ips = append(ips, dnsAnswer.IP.String())
					}
					dnsCounts.aIPs = append(dnsCounts.aIPs, ips)
					questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}] = dnsCounts

					// fmt.Println("dnsCounts.qCount: ", dnsCounts.qCount)
					// fmt.Println("dnsCounts.aCount: ", dnsCounts.aCount)
					// fmt.Println("dnsCounts.qTime: ", dnsCounts.qTime)
					// fmt.Println("dnsCounts.aIPs: ", dnsCounts.aIPs)

					if dnsCounts.qTime.Sub(packetTime).Seconds() > MAX_SECONDS_ELAPSED {
						
						fmt.Println("Time limit exceeded for spoofed response, so deleting it form map")
						// Remove entry from the map, as we only consider packets returning in a short span of time
						delete(questionToAnswerMap, DNSQuestion{uniqueID: int(dnsID)})
						
					} else if dnsCounts.aCount > dnsCounts.qCount {

						fmt.Println(time.Now().Format("2006-01-02 15:04:05.000000") + " !!!!!!!!! DNS SPOOFING ATTEMPT DETECTED !!!!!!!!!")
						// SImplifying it by assuming that the first question will always be the A type question
						domainFromQuestion := string(dns.Questions[0].Name)
						fmt.Println("TXID: " + strconv.Itoa(int(dnsID)) + ", DNSQuery: " + domainFromQuestion)
						for i := 0; i < len(dnsCounts.aIPs); i++ {
							fmt.Printf("Answer" + strconv.Itoa(i) + " %v\n", dnsCounts.aIPs[i])
						}
						questionToAnswerMap[DNSQuestion{uniqueID: int(dnsID)}] = dnsCounts

					}

				}
			}
		}
	}

}

func main() {

	var expression, fileName, iface string


	for i, v := range os.Args {
		if v == "-i" {
			iface = os.Args[i+1]
			fmt.Println("Interface specified by user: ", iface)
		} else if v == "-r" && iface == "" {
			fileName = os.Args[i+1]
			fmt.Println("FileName to read packets from: ", fileName)
		} else if i==1 && os.Args[i] != "-r" && os.Args[i] != "-i" && os.Args[i] != "-s" {
			expression = os.Args[i]
			fmt.Println("BPF filter specified by user: ", expression)
		} else if i > 0 && os.Args[i-1] != "-r" && os.Args[i-1] != "-i" && os.Args[i-1] != "-s" {
			expression = os.Args[i]
			fmt.Println("BPF filter specified by user: ", expression)
		}
	}

	var handle *pcap.Handle
	var err error

	if fileName != "" {
		fmt.Printf("Reading packets from file: " + fileName)
		fmt.Println()
		// fmt.Printlnt("Reading packets from file: " + *filePtr)
		fileNameStr := fileName
		handle, err = pcap.OpenOffline(fileNameStr)
		fmt.Printf("Opening file! %s", fileName)
	} else {
		var buffer = int32(1600)
		targetInterface := getTargetInterface(iface)
		handle, err = pcap.OpenLive(targetInterface, buffer, true, 30)
	}


	fmt.Println("Created handle!")

	if err != nil {
		fmt.Println("Printing error!")
		log.Fatal(err)
		fmt.Println("Done Printing error!")
	}

	if expression == "" {
		expression = "udp and port 53"
	} else if expression != "" {
		expression = "udp and port 53 and " + expression
		err = handle.SetBPFFilter(expression)
		if err != nil {
			log.Fatal(err)
		}
	}

	defer handle.Close()

	fmt.Println("Getting packets from source!")
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	questionToAnswerMap = make(map[DNSQuestion]DNSCounts)

	for packet := range src.Packets() {
		analyzePacket(packet)
	}
}
