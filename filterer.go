package main

import (
	"os"
	"fmt"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PhoneCall struct {
	to string
	from string
	sipId string
}

var matchedCalls map[string]PhoneCall

func createFilteredPcaps(inputFilename string, filters *map[string]string) (error){
	if err := validateInput(inputFilename, filters); err != nil{
		return err
	}
	
	if handle, err := pcap.OpenOffline(inputFilename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet.String())
			
			//if it's a matched INVITE, open a new call file and tag the handle as sipId:SIP_ID
			
			//if it's part of an existing matched call
				//write the packet to a file
				//if it declares a port to listen to, open a new tag in memory called "port:PORT" and point the tag to the existing file
			//if the current packet is a BYE, remove any port tags for this call
			
		}
		
		//Declare which calls we found and where they're saved
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