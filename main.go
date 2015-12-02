package main

import (
	"fmt"
	"log"
	"os"

	"github.com/phaxio/filterpcap/Godeps/_workspace/src/github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "filterpcap"
	app.Version = "0.1"
	app.Usage = "filterpcap someFile.pcap [options]"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "to",
			Usage: "Extract calls to a certain number",
		},
		cli.StringFlag{
			Name:  "callId",
			Usage: "Extract call with a specific SIP call ID",
		},
		cli.StringFlag{
			Name:  "outputDirectory, d",
			Usage: "Directory used to output filtered files",
			Value: "./",
		},
		cli.BoolFlag {
			Name: "debug",
			Usage: "Output debugging information",
		},
	}

	app.Action = func(c *cli.Context) {
		if len(c.Args()) == 0 {
			fmt.Println("You must specify a pcap filename")
			return
		}

		if c.String("to") != "" {
			Filters = append(Filters, PcapFilter{filterType: "to", value: c.String("to")}) 
		}
		
		if c.String("callId") != "" {
			Filters = append(Filters, PcapFilter{filterType: "callId", value: c.String("callId")})
		}
		
		err := createFilteredPcaps(c.Args()[0], c.String("outputDirectory"), c.Bool("debug"))

		if err != nil {
			log.Fatal(err)
		}
	}

	app.Run(os.Args)
}

