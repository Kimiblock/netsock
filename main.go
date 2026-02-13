package main

import (
	//"fmt"
	"log"
	"net"
	//"os"
	"strings"

	"golang.org/x/sys/unix"

	"net"

	"github.com/Kimiblock/pecho"
	"github.com/google/nftables"
)

const (
	version		float32	=	0.1
)

var (
	connNft		*nftables.Conn
	err		error
	logChan		= pecho.MkChannel()
)

/* Special strings may be interpreted
	private		10.0.0.0 - 10.255.255.255, 172.16.0.0 - 172.31.255.255, 192.168.0.0 - 192.168.255.255 and fd00::/8
	Custom IPs not supported yet.
*/
type appOutPerms struct {
	allowIP			[]string
	denyIP			[]string
	appID			[]string
	appGPath		string
}

func echo(lvl string, msg string) {
	logChan <- []string{lvl, msg}
}

/*
	This builds a nft file, caller should close channel to indicate done
*/
func buildNftFile (
	nftchan chan string,
	builder strings.Builder,
	tableName string,
	outperm appOutPerms,
) string {
	if outperm.appID == "" {
		echo("warn", "This appID is invalid")
		return
	}
	v4DenyList := []string{}
	v6DenyList := []string{}
	for idx, val := range outperm.denyIP {
		switch val {
			case "private":
				v4DenyList = append(
					v4DenyList,
					"10.0.0.0/8",
					"172.16.0.0/12",
					"192.168.0.0/16",
				)
				v6DenyList = append(
					v6DenyList,
					"fd00::/8",
				)
			default:
				echo("debug", "Trying to resolve: " + val)
				ipRes := net.ParseIP(val)
				if ipRes != nil {
					tryResv4 := ipRes.To4()
					switch tryResv4 {
						case nil:
							echo("debug", "Resolved " + val + " as IPv6")
							v6DenyList = append(v6DenyList, string(ipRes))
							continue
						default:
							echo("debug", "Resolved " + val + " as IPv4")
							v4DenyList = append(v4DenyList, string(ipRes.To4()))
							continue
					}
				}
		}
	}




	builder.WriteString("table inet " + tableName + " {\n")

	builder.WriteString("chain charcoal {\n")
		builder.WriteString("type filter hook output priority filter; policy accept; {\n")
			builder.WriteString("tcp dport 53 accept")
			builder.WriteString("udp dport 53 accept")
			builder.WriteString(
				"socket cgroupv2 level 6 " + outperm.appGPath + " ip daddr @v4reject drop\n",
			)
			builder.WriteString(
				"socket cgroupv2 level 6 " + outperm.appGPath + " ip daddr @v6reject drop \n",
			)
		builder.WriteString("}\n")
	builder.WriteString("}\n")


	builder.WriteString("\n}")
}

/* Returns whether the operation is success or not */
func setAppPerms(appCgroup string, outperm appOutPerms, appID string, sandboxEng string) bool {
	logChan <- []string{
		"debug",
		"Got firewall rules for " + appID + " from " + sandboxEng,
	}
	var table = nftables.Table {
		Name:	sandboxEng + "-" + appID,
		Family:	unix.NFPROTO_INET,
	}
	tableExt, errList := connNft.ListTableOfFamily(
		sandboxEng + "-" + appID,
		unix.NFPROTO_INET,
	)
	if errList != nil {
		log.Println("Error listing table: " + errList.Error() + ", treating as non-existent")
	} else if tableExt == nil {
		log.Println("Got nil from ListTable")
	} else {
		connNft.DelTable(&table)
		log.Println("Deleted previous table")
	}

	builder := strings.Builder{}

	nftChan := make(chan nftType, 10)
	nftFile := buildNftFile(nftChan, builder, sandboxEng + "-" + appID)

	nftChan <-


	return true
}

func main() {
	go pecho.StartDaemon(logChan)
	log.Println("Starting charcoal", version, ", establishing connection to nftables")
	connNft, err = nftables.New()
	if err != nil {
		log.Fatalln("Could not establish connection to nftables: " + err.Error())
	}
	log.Println("Established connection")
}