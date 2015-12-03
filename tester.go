package main

import (
	"fmt"
	"github.com/phaxio/sip_parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"strings"
)

func runTestZone(){
	fmt.Println("We're in test zone")
	if handle, err := pcap.OpenOffline("/home/jnankin/Desktop/test.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			
			if packet.Layer(layers.LayerTypeTCP) != nil {
				appLayer := packet.ApplicationLayer()
				fmt.Println("APP LAYER: \n" + string(appLayer.Payload()) + "\n\n");
				
				sipMessage := sipparser.ParseMsg(string(appLayer.Payload()))
				fmt.Println("SIP BODY: \n" + sipMessage.Body + "\n\n");
				fmt.Println("Content length: \n" + sipMessage.ContentLength + "\n\n");
				
				/*SIP PDU detection: 1st Line contains SIP/2.0

foreach line, if it's a content length, set it.
    add each line to the current sip message
    if the line is blank:
        if I have a content length:
         add content length more bytes from the message to the current sip message
        
        add the current message to the list of messages found

if there are still messages in the buffer, the packet is fragmented and we need more messages

				*/
			}
		}
	}
}

func splitForSipMessages(packetBody string) []string, bool {
	var messages []string
	var currentBody := packetBody
	
	for sipMessage, remainingBody := readSipMessageFromString(currentBody){
		if sipMessage == "" && len(remainingBody) > 0 {
			panic("There's a problem")
		} else if sipMessage == "" && remainingBody == "" {
			return messages, true
		}
		else {
			//add the sip message
			
			
			if remainingBody != "" {
				return messages, false
			}
		}
		
	}
}

func readSipMessageFromString(packetBody string) parsedMessage, remainingBody {
	lines := strings.Split(packetBody, "\r\n")
	contentLength := 0
	
	//get index of a double line
	//if the first line of this returned text does not contain SIP, just return
	//get content length
	
	//return the string from 0 until index + 4 + contentLength, and another string starting from then to the end
}

