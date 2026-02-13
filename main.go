package main

import (
	//"fmt"
	"log"
	//"os"
	"golang.org/x/sys/unix"
	//"strings"
	"net"

	"github.com/google/nftables"
	"github.com/Kimiblock/pecho"
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
	allowIP		[]string
	denyIP		[]string
}

func echo(lvl string, msg string) {
	logChan <- []string{lvl, msg}
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


	tableRet := connNft.AddTable(&table)

	dropPolicy := nftables.ChainPolicyDrop

	// Build drop policy first
	var chain = nftables.Chain {
		Name:		"Denylist",
		Table:		tableRet,
		Hooknum:	nftables.ChainHookOutput,
		Priority:	nftables.ChainPrioritySecurity,
		Type:		nftables.ChainTypeFilter,
		Policy:		&dropPolicy,
	}

	denyList := []string{}
	rejectSet4 := nftables.Set {
		Table:		tableRet,
		Name:		"Denylist",
		Interval:	true,
		KeyType:	nftables.TypeIPAddr,
	}
	rejElement4 := []nftables.SetElement {}
	rejectSet6 := nftables.Set {
		Table:		tableRet,
		Name:		"Denylist6",
		Interval:	true,
		KeyType:	nftables.TypeIP6Addr,
	}
	rejElement6 := []nftables.SetElement {}
	// Here comes the rules
	for _, rule := range outperm.denyIP {
		echo("debug", "Processing rule: " + rule)
		switch rule {
			case "private":
				rejElement4 = append(rejElement4, []nftables.SetElement{
					{
						Key:		net.ParseIP("10.0.0.0").To4(),
						KeyEnd:		net.ParseIP("10.255.255.255").To4(),
					},
					{
						Key:		net.ParseIP("172.16.0.0").To4(),
						KeyEnd:		net.ParseIP("172.31.255.255").To4(),
					},
					{
						Key:		net.ParseIP("192.168.0.0").To4(),
						KeyEnd:		net.ParseIP("192.168.255.255").To4(),
					},
				}...)
				rejElement6 = append(rejElement6, []nftables.SetElement{
					{
						Key:		net.ParseIP("fd00::"),
						KeyEnd:		net.ParseIP("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
					},

				}...)
		}
	}
	err = connNft.AddSet(&rejectSet4, rejElement4)
	if err != nil {
		echo("debug", "Could not add IPv4 set for blocking: " + err.Error())
	}
	err = connNft.AddSet(&rejectSet6, rejElement6)
	if err != nil {
		echo("debug", "Could not add IPv6 set for blocking: " + err.Error())
	}

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