package main

import (
	"os"
	"fmt"
	"errors"
	"strings"
	"strconv"
	"regexp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phaxio/sip_parser"
)

type PhoneCall struct {
	to string
	from string
	sipId string
}

type SIPPacket struct {
	messageType	string
	callId		string
	mediaPort	string		
	srcIP 		string
	dstIP 		string
	srcPort 	string
	dstPort 	string
	packet		*gopacket.Packet
}

var matchedCalls map[string]PhoneCall
var mediaLineRegex = regexp.MustCompile("^m=(.*)$")

func createFilteredPcaps(inputFilename string, filters *map[string]string) (error){
	if err := validateInput(inputFilename, filters); err != nil{
		return err
	}
	
	if handle, err := pcap.OpenOffline(inputFilename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			
			if parsedSipPacket := parseForSip(packet); parsedSipPacket != nil {
				//if it's a matched INVITE, open a new call file and tag the handle as sipId:SIP_ID
				
				//if it's part of an existing matched call
					//write the packet to a file
					//if it declares a port to listen to, open a new tag in memory called "port:PORT" and point the tag to the existing file
				//if the current packet is a BYEs, remove any port tags for this call
			}
		}
		
		//Declare which calls we found and where they're saved
	}
	
	return nil
}

func parseForSip(packet gopacket.Packet) *SIPPacket {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	appLayer := packet.ApplicationLayer()
	
	if ipLayer != nil && appLayer != nil && strings.Contains(string(appLayer.Payload()), "SIP") {
		sipMessage := sipparser.ParseMsg(string(appLayer.Payload()))
		
		if sipMessage != nil {
			sipPacket := new(SIPPacket)
 			ip, _ := ipLayer.(*layers.IPv4)
 			
 			//Set the ports 
 			if ip.Protocol == layers.IPProtocolTCP {
			 	protocol, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		 		sipPacket.srcIP = ip.SrcIP.String()
		 		sipPacket.dstIP = ip.DstIP.String()
		 		sipPacket.srcPort = strconv.Itoa(int(protocol.SrcPort))
		 		sipPacket.dstPort = strconv.Itoa(int(protocol.DstPort))
			} else if ip.Protocol == layers.IPProtocolUDP {
 				protocol, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		 		sipPacket.srcIP = ip.SrcIP.String()
		 		sipPacket.dstIP = ip.DstIP.String()
		 		sipPacket.srcPort = strconv.Itoa(int(protocol.SrcPort))
		 		sipPacket.dstPort = strconv.Itoa(int(protocol.DstPort))
 			}
			
			fmt.Println("\n\n New sip packet")
			fmt.Println("===================")
			fmt.Println(sipPacket.srcIP, sipPacket.srcPort)
			fmt.Println(sipPacket.dstIP, sipPacket.dstPort)
			fmt.Println("Content-Type: " + sipMessage.ContentType)
			if sipMessage.StartLine.Type == sipparser.SIP_REQUEST {
				fmt.Println("Received SIP request ")
				fmt.Println("method: " + sipMessage.StartLine.Method)
				fmt.Println("callId: " + sipMessage.CallId)
				fmt.Println("body: " + string(appLayer.Payload()))
			} else if sipMessage.StartLine.Type == sipparser.SIP_RESPONSE {
				fmt.Println("Received SIP response")
				fmt.Println("Status: " + sipMessage.StartLine.RespText)
				fmt.Println("callId: " + sipMessage.CallId)
				fmt.Println("body: " + string(appLayer.Payload()))
			}
			
			fmt.Println(mediaLineRegex.FindAllString(sipMessage.Body, 0))
			
			
			
			return sipPacket
		}			
		
	}
	
	return nil
}


func validateInput(inputFilename string , filters *map[string]string) (error){
	if _, err := os.Stat(inputFilename); os.IsNotExist(err) {
		return fmt.Errorf("no such file or directory: %s\n", inputFilename)
	}
	
	if len(*filters) == 0{
		return errors.New("You must specify at least one filter for the pcap.")
	}
	
	return nil
}