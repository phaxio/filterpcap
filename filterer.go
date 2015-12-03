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


//Map from port:seqNumber to previous packet
var expectedTCPPackets = make(map[string]*gopacket.Packet)

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

func matchesFilters(sipMessage sipparser.SipMsg) bool {
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
			isSipPacket := false
			
			//if this is not a UDP or TCP packet, just move along
			if packetInfo == nil {
				continue;
			}

			if packetIsContinuation(packet){
				//construct the fragmented sip message
				//test it and write it out if necessary
				//remove the packet from expectedTCPPackets
				isSipPacket = true
			}
			
			completeSipMessages, isFragmented := parseForSipMessages(packet)
			if isFragmented {
				//add this packet to expectedTCPPackets keyed by port and expected seq number
			}
			
			if len(completeSipMessages) > 0 {
				isSipPacket = true
				for _, sipMessage := range completeSipMessages {
					writeIfMatchedSipMessage(sipMessage, []gopacket.Packet{packet}, *packetInfo)
				}
			}
			
			_, packetDirectedToMonitoredMediaPort := monitoredMediaPorts[packetInfo.SrcIpAndPort()];
			if !isSipPacket && packetDirectedToMonitoredMediaPort {
				writePackets([]gopacket.Packet{packet}, monitoredMediaPorts[packetInfo.SrcIpAndPort()])
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

//Take the body, look for SIP messages.  If they exist, split them up and return them.
//If we find that the last message is fragmented, do not return it in the list and return false 
func parseForSipMessages(packet gopacket.Packet) ([]sipparser.SipMsg, bool){
	/*ipLayer := packet.Layer(layers.LayerTypeIPv4)
	appLayer := packet.ApplicationLayer()
	
	fmt.Println("PAYLOAD: " + string(appLayer.Payload()) + " - END.")
	if ipLayer != nil && appLayer != nil && strings.Contains(string(appLayer.Payload()), "SIP") {
		return sipparser.ParseMsg(string(appLayer.Payload()))
	}

	return nil*/
	
	return nil, false
}

func packetIsContinuation(packet gopacket.Packet) (bool){
	return false
}

func writeIfMatchedSipMessage(sipMessage sipparser.SipMsg, packetsInvolved []gopacket.Packet, packetInfo PacketInfo) (bool){
	if matchesFilters(sipMessage) {
		if _, found := matchedCalls[sipMessage.CallId]; !found {
			toNumber, _ := normalizeNumber(sipMessageNumberToString(sipMessage.To))
			fromNumber, _ := normalizeNumber(sipMessageNumberToString(sipMessage.From))
			phoneCall := PhoneCall{from: fromNumber, to: toNumber, callId: sipMessage.CallId, mediaPorts: map[string]bool{}}
			matchedCalls[sipMessage.CallId] = &phoneCall
		}
		
		if sipMessage.ContentType == CONTENT_TYPE_SDP {
			mediaPort, err := extractMediaPortFromSDP(sipMessage)
			if err != nil {
				log.Panicln(err)
			}
			
			//put that tag in
			monitoredMediaPorts[packetInfo.srcIP + ":" + mediaPort] = matchedCalls[sipMessage.CallId]
			phoneCall := *matchedCalls[sipMessage.CallId]
			phoneCall.mediaPorts[packetInfo.srcIP + ":" + mediaPort] = true
		}
		
		//if it's a BYE, clean up any port related tags
		if (sipMessage.StartLine.Method == "BYE"){
			for mediaIpAndPort, _ := range matchedCalls[sipMessage.CallId].mediaPorts {
				delete(monitoredMediaPorts, mediaIpAndPort)
			}
			
			//clear the ports list
			for k := range matchedCalls[sipMessage.CallId].mediaPorts{
			    delete(matchedCalls[sipMessage.CallId].mediaPorts, k)
			}
		}
		
		writePackets(packetsInvolved, matchedCalls[sipMessage.CallId])
		return true
	}
	return false
}

func writePackets(packets []gopacket.Packet, phoneCall *PhoneCall) {
	
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

func extractMediaPortFromSDP(sipMsg sipparser.SipMsg) (string, error) {
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
