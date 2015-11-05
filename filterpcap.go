package main

import (
	"fmt"
	"github.com/phaxio/filterpcap/Godeps/_workspace/src/github.com/codegangsta/cli"
	"os"
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
		} else if _, err := os.Stat(c.Args()[0]); os.IsNotExist(err) {
			fmt.Printf("no such file or directory: %s\n", c.Args()[0])
			return
		} else if !hasFilters(c) {
			fmt.Println("You must specify at least one filter for the pcap.")
			return
		}
	}

	app.Run(os.Args)
}

func hasFilters(c *cli.Context) bool {
	return c.String("to") != "" || c.String("callId") != "" || c.String("sipCode") != ""
}
