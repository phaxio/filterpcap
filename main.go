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
			Name:  "sipCode",
			Usage: "Extract calls containing SIP packets with a certain status code",
		},
	}

	app.Action = func(c *cli.Context) {
		if len(c.Args()) == 0 {
			fmt.Println("You must specify a pcap filename")
			return
		}

		err := createFilteredPcaps(c.Args()[0], loadFilters(c))

		if err != nil {
			log.Fatal(err)
		}
	}

	app.Run(os.Args)
}

func loadFilters(c *cli.Context) *map[string]string {
	filters := make(map[string]string)

	if c.String("to") != "" {
		filters["to"] = c.String("to")
	}

	if c.String("callId") != "" {
		filters["callId"] = c.String("callId")
	}

	if c.String("sipCode") != "" {
		filters["sipCode"] = c.String("sipCode")
	}

	return &filters
}
