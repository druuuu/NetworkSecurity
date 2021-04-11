

package main

import (
    "flag"
    "fmt" //for loggin errors
    "log"
    "os"
    "time"

    //for parsing command line arguments
    "strconv"

    "github.com/google/gopacket" //for gopacket
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap" //for pcap
)

var (
    devName    string
    es_index   string
    es_docType string
    es_server  string
    err        error
    handle     *pcap.Handle
    InetAddr   string
    SrcIP      string
    DstIP      string
)

type DnsMsg struct {
    Timestamp       string
    SourceIP        string
    DestinationIP   string
    DnsQuery        string
    DnsAnswer       []string
    DnsAnswerTTL    []string
    NumberOfAnswers string
    DnsResponseCode string
    DnsOpCode       string
}

func isUniquePresent(listOne, listTwo []string) bool {
    duplicate := false
    for _, i := range listOne {
        duplicate = false
        for _, j := range listTwo {
            if i == j {
                duplicate = true
                break
            }
        }
        if !duplicate {
            break
        }
    }

    if duplicate {
        for _, i := range listTwo {
            duplicate = false
            for _, j := range listOne {
                if i == j {
                    duplicate = true
                    break
                }
            }
            if !duplicate {
                break
            }
        }
    }

    return !duplicate
}

func main() {

    interfacePtr := flag.String("i", "", "Interface to capture from. If blank a default interface will be chosen (Use either interface or file)")
    filePtr := flag.String("r", "", "File to read packets from (Use either interface or file)")
    grepPtr := flag.String("s", "", "String to match in the packets")
    flag.Parse()
    expression := ""

    argsArr := flag.Args()
    if len(argsArr) > 0 {
        expression = argsArr[0]
    }

    if *interfacePtr != "" && *filePtr != "" {
        flag.PrintDefaults()
        os.Exit(1)
    }

    fmt.Printf("Using: \n\tInterface: %s\n\tFile: %s\n\tFilterString: %s\n\tExpression: %s\n", *interfacePtr, *filePtr, *grepPtr, expression)

    var handle *pcap.Handle
    var err error

    // if *filePtr != "" {
    //  handle, err = pcap.OpenOffline(*filePtr)
    // } else {
    //  var buffer = int32(1600)
    //  targetInterface := getTargetInterface(*interfacePtr)
    //  handle, err = pcap.OpenLive(targetInterface, buffer, true, 30)
    // }

    handle, err = pcap.OpenLive("eth0", 1600, false, pcap.BlockForever)

    if err != nil {
        log.Fatal(err)
    }

    if expression != "" {
        err = handle.SetBPFFilter(expression)
        if err != nil {
            log.Fatal(err)
        }
    }

    defer handle.Close()

    var eth layers.Ethernet
    var ip4 layers.IPv4
    var ip6 layers.IPv6
    var tcp layers.TCP
    var udp layers.UDP
    var dns layers.DNS
    var payload gopacket.Payload

    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &dns, &payload)
    decodedLayers := make([]gopacket.LayerType, 0, 10)
    nameToDstToIdToIpList := make(map[string]map[string]map[string][]string)
    queryTimeMap := make(map[string]time.Time)
    fmt.Println("New maps created")

    for {

        data, _, err := handle.ReadPacketData()
        if err != nil {
            fmt.Println("Error reading packet data: ", err)
            continue
        }

        err = parser.DecodeLayers(data, &decodedLayers)
        for _, typ := range decodedLayers {
            switch typ {
            case layers.LayerTypeIPv4:
                SrcIP = ip4.SrcIP.String()
                DstIP = ip4.DstIP.String()
            case layers.LayerTypeIPv6:
                SrcIP = ip6.SrcIP.String()
                DstIP = ip6.DstIP.String()
            case layers.LayerTypeDNS:

                dnsOpCode := int(dns.OpCode)
                dnsResponseCode := int(dns.ResponseCode)
                dnsANCount := int(dns.ANCount)
                // dnsID := string(dns.ANCount)
                dnsID := strconv.Itoa(int(dns.ANCount))

                if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {

                    fmt.Println("------------------------")
                    fmt.Println("    DNS Record Detected")

                    for _, dnsQuestion := range dns.Questions {

                        t := time.Now()
                        timestamp := t.Format(time.RFC3339)

                        // Add a document to the index
                        d := DnsMsg {
							Timestamp: timestamp, SourceIP: SrcIP,
                            DestinationIP:   DstIP,
                            DnsQuery:        string(dnsQuestion.Name),
                            DnsOpCode:       strconv.Itoa(dnsOpCode),
                            DnsResponseCode: strconv.Itoa(dnsResponseCode),
                            NumberOfAnswers: strconv.Itoa(dnsANCount)
						}
                        fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
                        fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
                        fmt.Println("    DNS # Answers: ", strconv.Itoa(dnsANCount))
                        fmt.Println("    DNS Question: ", string(dnsQuestion.Name))
                        fmt.Println("    DNS Endpoints: ", SrcIP, DstIP)

                        fmt.Println(dns.ARCount, dns.ID, dns.NSCount, dns.QDCount, dns.Z)

                        t1 := time.Now()
                        // check if the map already has record for this domain name
                        if _, containsQuestion := nameToDstToIdToIpList[string(dnsQuestion.Name)]; containsQuestion {
                            // check if the already existing DNS question for this domain name is stale
                            if t1.Sub(queryTimeMap[string(dnsQuestion.Name)]).Seconds() > 60 {
                                // if stale, clear it from both maps
                                fmt.Println("Clearing maps")
                                delete(nameToDstToIdToIpList, string(dnsQuestion.Name))
                                delete(queryTimeMap, string(dnsQuestion.Name))
                            }
                        }

                        if _, containsName := nameToDstToIdToIpList[string(dnsQuestion.Name)]; !containsName {
                            nameToDstToIdToIpList[string(dnsQuestion.Name)] = make(map[string]map[string][]string)
                        }

                        // add current time to the queryTimeMap to check next if it's stale next time
                        queryTimeMap[string(dnsQuestion.Name)] = t1
                        var currIPList []string

                        if dnsANCount > 0 {

                            for _, dnsAnswer := range dns.Answers {
                                d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
                                if dnsAnswer.IP.String() != "<nil>" {
                                    fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
                                    currIPList = append(currIPList, dnsAnswer.IP.String())
                                    //nameToDstToIpList[string(dnsQuestion.Name)][string(DstIP)] = append(nameToDstToIpList[string(dnsQuestion.Name)][string(DstIP)], dnsAnswer.IP.String())
                                    d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
                                }
                            }

                        }

                        fmt.Println("Map: ", nameToDstToIdToIpList)
                        _, ok := nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID]
                        fmt.Println("If check: ", ok, "question: ", string(dnsQuestion.Name), "dstIP:", string(DstIP), "dnsID: ", dnsID)
                        // check if there are IP resolutions provided by for this question and DstIP already (we have already cleared them if stale on line 305)
                        if _, containsQuestion := nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID]; containsQuestion {
                            oldIPList := nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID]

                            uniquePresent := isUniquePresent(oldIPList, currIPList)
                            nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID] = currIPList

                            if uniquePresent {
                                fmt.Println("There is a difference between IPs provided within the last 1 minute by resolver. You might be under attack.")
                                fmt.Println("OldIPList:", oldIPList)
                                fmt.Println("NewIPList:", currIPList)
                            } else {
                                fmt.Println("NO ongoing attack.")
                            }
                        } else {
                            fmt.Println("Setting the currIPList to map")
                            if _, contain := nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)]; !contain {
                                nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)] = make(map[string][]string)
                            }
                            nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID] = currIPList
                            _, ok := nameToDstToIdToIpList[string(dnsQuestion.Name)][string(DstIP)][dnsID]
                            fmt.Println("testing If check: ", ok, "question: ", string(dnsQuestion.Name), "dstIP:", string(DstIP), "dnsID: ", dnsID)
                        }

                    }
                }

            }
            // t2 := time.Now()

        }

        // fmt.Println(nameToDstToIpList)

        if err != nil {
            fmt.Println("  Error encountered:", err)
        }
    }

    // src := gopacket.NewPacketSource(handle, handle.LinkType())

    // for packet := range src.Packets() {
    //  printPacket(packet, *grepPtr)
    // }
}

