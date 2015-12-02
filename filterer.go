package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phaxio/sip_parser"
	"github.com/ttacon/libphonenumber"
)

const CONTENT_TYPE_SDP string = "application/sdp"

var matchedCalls = make(map[string]*PhoneCall)
var monitoredMediaPorts = make(map[string]*PhoneCall)

var mediaRegex = regexp.MustCompile("(?m)^m=(.*)$")
var sip = regexp.MustCompile("")
var Filters []PcapFilter

type PhoneCall struct {
	to    		string
	from  		string
	callId 		string
	mediaPorts  map[string]bool
	numPackets	int
}

type PacketInfo struct {
	srcIP   string
	dstIP   string
	srcPort string
	dstPort string
}

func (pi *PacketInfo) SrcIpAndPort() (string) {
	return pi.srcIP + ":" + pi.srcPort 
}

func (pi *PacketInfo) DstIpAndPort() (string) {
	return pi.dstIP + ":" + pi.dstPort 
}


type PcapFilter struct {
	filterType string
	value      string
}

func sipMessageNumberToString(number *sipparser.From) (string){
	return number.URI.User
}

func matchesFilters(sipMessage *sipparser.SipMsg) bool {
	for _, filter := range Filters {
		if filter.filterType == "to" && phoneNumbersMatch(sipMessageNumberToString(sipMessage.To), filter.value){
			return true
		} else if filter.filterType == "callId" && sipMessage.CallId == filter.value {
			return true
		}
	}

	return false
}


func createFilteredPcaps(inputFilename string, directoryPrefix string, debug bool) error {
	packetCounter := 1
	
	if err := validateInput(inputFilename); err != nil {
		return err
	}

	if handle, err := pcap.OpenOffline(inputFilename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if debug {
				log.Println(fmt.Sprintf("Processing packet #%d",packetCounter))
			}
			packetCounter++

			
			packetInfo := getPacketInfo(packet)
			
			if packetInfo == nil {
				continue;
			}

			if sipPacket := parseForSip(packet); sipPacket != nil {
				if matchesFilters(sipPacket) {
					//add the packet to the list
					//0c0422ad-fd0a-1233-108e-02dbda1bcd05
					
					if _, found := matchedCalls[sipPacket.CallId]; !found {
						toNumber, _ := normalizeNumber(sipMessageNumberToString(sipPacket.To))
						fromNumber, _ := normalizeNumber(sipMessageNumberToString(sipPacket.From))
						phoneCall := PhoneCall{from: fromNumber, to: toNumber, callId: sipPacket.CallId, mediaPorts: map[string]bool{}}
						matchedCalls[sipPacket.CallId] = &phoneCall
					}
					
					if sipPacket.ContentType == CONTENT_TYPE_SDP {
						mediaPort, err := extractMediaPortFromSDP(sipPacket)
						if err != nil {
							log.Panicln(err)
						}
						
						//put that tag in
						monitoredMediaPorts[packetInfo.srcIP + ":" + mediaPort] = matchedCalls[sipPacket.CallId]
						phoneCall := *matchedCalls[sipPacket.CallId]
						phoneCall.mediaPorts[packetInfo.srcIP + ":" + mediaPort] = true
					}
					
					//if it's a BYE, clean up any port related tags
					if (sipPacket.StartLine.Method == "BYE"){
						for mediaIpAndPort, _ := range matchedCalls[sipPacket.CallId].mediaPorts {
							delete(monitoredMediaPorts, mediaIpAndPort)
						}
						
						//clear the ports list
						for k := range matchedCalls[sipPacket.CallId].mediaPorts{
						    delete(matchedCalls[sipPacket.CallId].mediaPorts, k)
						}
					}
					
					writePacket(packet, matchedCalls[sipPacket.CallId])
					
				} else {
					continue
				}
			} else if _, ok := monitoredMediaPorts[packetInfo.SrcIpAndPort()]; ok {
				writePacket(packet, monitoredMediaPorts[packetInfo.SrcIpAndPort()])
			}
		}
		
		if len(matchedCalls) > 0 {
			lineFormat := "%-40s | %-15s | %-15s | %-30s"
			
		
			log.Println(fmt.Sprintf(lineFormat, "Call ID", "To", "From", "Output Filename"))
			log.Println(fmt.Sprintf(lineFormat, "========================================", "===============", "===============", "=============================="))
			
			
			//Declare which calls we found and where they're saved
			for _, call := range matchedCalls {
				log.Println(fmt.Sprintf(lineFormat, call.callId, call.to, call.from, "")) 
			}	
		} else {
			return errors.New("No calls found in the provided capture.")
		}
	}

	return nil
}

func writePacket(packet gopacket.Packet, phoneCall *PhoneCall) {
	
}

func phoneNumbersMatch(num1, num2 string) (bool){
	normalized1, err := normalizeNumber(num1)
	
	if err != nil {
		panic(err)
	}
	
	normalized2, err := normalizeNumber(num1)
	
	if err != nil {
		panic(err)
	}
	
	return normalized1 == normalized2
}

func parseForSip(packet gopacket.Packet) *sipparser.SipMsg {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	appLayer := packet.ApplicationLayer()
	fmt.Println("PAYLOAD: " + string(appLayer.Payload()) + " - END.")
	if ipLayer != nil && appLayer != nil && strings.Contains(string(appLayer.Payload()), "SIP") {
		return sipparser.ParseMsg(string(appLayer.Payload()))
	}

	return nil
}

func getPacketInfo(packet gopacket.Packet) *PacketInfo {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var packetInfo PacketInfo

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		//Set the ports
		if ip.Protocol == layers.IPProtocolTCP {
			protocol, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
			packetInfo.srcIP = ip.SrcIP.String()
			packetInfo.dstIP = ip.DstIP.String()
			packetInfo.srcPort = strconv.Itoa(int(protocol.SrcPort))
			packetInfo.dstPort = strconv.Itoa(int(protocol.DstPort))
		} else if ip.Protocol == layers.IPProtocolUDP {
			protocol, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			packetInfo.srcIP = ip.SrcIP.String()
			packetInfo.dstIP = ip.DstIP.String()
			packetInfo.srcPort = strconv.Itoa(int(protocol.SrcPort))
			packetInfo.dstPort = strconv.Itoa(int(protocol.DstPort))
		}
	}

	return &packetInfo
}

func validateInput(inputFilename string) error {
	if _, err := os.Stat(inputFilename); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("no such file or directory: %s\n", inputFilename))
	}

	if len(Filters) == 0 {
		return errors.New("You must specify at least one filter for the pcap.")
	}

	return nil
}

func extractMediaPortFromSDP(sipMsg *sipparser.SipMsg) (string, error) {
	matches := mediaRegex.FindAllStringSubmatch(sipMsg.Body, -1)
	if len(matches) > 1 {
		fmt.Println(matches)
		fmt.Println(sipMsg.Body)
		return "", errors.New(fmt.Sprintf("Attempted to parse media line from SDP, but found %d lines!", len(matches)))
	} else if len(matches) == 0 {
		return "", errors.New("Attempted to parse media line from SDP, but could not find a media line!")
	}

	//parse port out of media line
	return strings.Fields(matches[0][1])[1], nil
}

func normalizeNumber(number string) (string, error) {
	if utf8.RuneCountInString(number) == 10 && !strings.HasPrefix(number, "+") {
		number = "1" + number
	}
	
	if !strings.HasPrefix(number, "+"){
		number = "+" + number
	}
	
	phoneNum, err := libphonenumber.Parse(number, "US")
	
	if err != nil {
		return "", err
	}
	
	return libphonenumber.Format(phoneNum,libphonenumber.E164), nil
}
