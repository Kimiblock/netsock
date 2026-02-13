package main

import (
	//"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"encoding/json"
	"golang.org/x/sys/unix"

	"os/signal"
	"syscall"
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
	other strings are resolved to IP addresses
*/
type appOutPerms struct {
	//allowIP			[]string
	denyIP			[]string
	appID			[]string
	appGPath		string
}

type sigResponse struct {
	success			bool
	log			string
}

func echo(lvl string, msg string) {
	logChan <- []string{lvl, msg}
}

/*
	This builds a nft file, caller should close channel to indicate done
*/
func buildNftFile (
	tableName string,
	outperm appOutPerms,
) string {
	builder := strings.Builder{}
	if len(outperm.appID) == 0 {
		echo("warn", "This appID is invalid")
		return ""
	}
	v4DenyList := []string{}
	v6DenyList := []string{}
	for _, val := range outperm.denyIP {
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
							v6DenyList = append(v6DenyList, ipRes.String())
							continue
						default:
							echo("debug", "Resolved " + val + " as IPv4")
							v4DenyList = append(v4DenyList, ipRes.To4().String())
							continue
					}
				} else {
					addrs, err := net.LookupHost(val)
					if err != nil {
						echo(
						"warn",
						"Could not resolve host " + val + ": " + err.Error(),
						)
					}
					for _, addr := range addrs {
						tryResV4 := net.ParseIP(addr)
						switch tryResV4 {
							case nil:
								v6DenyList = append(
									v6DenyList,
									tryResV4.String(),
								)
							default:
								v4DenyList = append(
									v4DenyList,
									tryResV4.To4().String(),
								)
						}
					}
				}
		}
	}






	builder.WriteString("table inet " + tableName + " {\n")

	builder.WriteString("set v4reject {\n")
		builder.WriteString("type ipv4_addr;\n")
		builder.WriteString("flags interval;\n")
			builder.WriteString("elements = {\n")
			for idx, val := range v4DenyList {
				if idx > 0 {
					builder.WriteString(",\n")
				}
				builder.WriteString(val)
			}
			builder.WriteString("}\n")
	builder.WriteString("}\n")

	builder.WriteString("set v6reject {\n")
		builder.WriteString("type ipv6_addr;\n")
		builder.WriteString("flags interval;\n")
			builder.WriteString("elements = {\n")
			for idx, val := range v6DenyList {
				if idx > 0 {
					builder.WriteString(",\n")
				}
				builder.WriteString(val)
			}
			builder.WriteString("}\n")
	builder.WriteString("}\n")

	builder.WriteString("chain charcoal {\n")
		builder.WriteString("type filter hook output priority filter;\n")
		builder.WriteString("policy accept;\n")
		builder.WriteString(
			"socket cgroupv2 level 6 " + strconv.Quote(outperm.appGPath) + " tcp dport 53 accept\n",
		)
		builder.WriteString(
			"socket cgroupv2 level 6 " + strconv.Quote(outperm.appGPath) + " udp dport 53 accept\n",
		)
		builder.WriteString(
			"socket cgroupv2 level 6 " + strconv.Quote(outperm.appGPath) + " ip daddr @v4reject drop\n",
		)
		builder.WriteString(
			"socket cgroupv2 level 6 " + strconv.Quote(outperm.appGPath) + " ip6 daddr @v6reject drop\n",
		)

	builder.WriteString("}\n")


	builder.WriteString("}\n")

	return builder.String()
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

	nftFile := buildNftFile(sandboxEng + "-" + appID, outperm)
	if len(nftFile) == 0 {
		echo("warn", "Could not read generated nftfile")
		return false
	}

	echo("debug", "Got generated rule: " + nftFile)


	cmd := exec.Command("nft", "-c", "-f")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		echo("warn", "Could not pipe stdin" + err.Error())
		return false
	}
	_, err = io.WriteString(stdin, nftFile)
	if err != nil {
		echo("warn", "Could not write stdin: " + err.Error())
		return false
	}
	stdin.Close()

	err = cmd.Wait()
	if err != nil {
		echo("warn", "nft failed to test rules: " + err.Error())
		return false
	}


	return true
}

func sendResponse (writer http.ResponseWriter, response sigResponse) {
	jsonObj, err := json.Marshal(response)
	if err != nil {
		echo("warn", "Could not marshal response, falling back to standard response")
		var respFallback sigResponse
		respFallback.success = false
		respFallback.log = "Could not marshal original response"
		jsonObj, _ := json.Marshal(respFallback)
		writer.Write(jsonObj)
	}

	writer.Write(jsonObj)
}

func unknownReqHandler (writer http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	var resp sigResponse
	resp.success = false
	resp.log = "Unknown operation"
	sendResponse(writer, resp)
}

func shutdownWorker (shutdownChan chan os.Signal) {
	sig := <- shutdownChan
	echo("info", "Shutting down charcoal on signal " + sig.String())
	connNft.CloseLasting()
}

func main() {
	sigChan := make(chan os.Signal, 1)
	go shutdownWorker(sigChan)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go pecho.StartDaemon(logChan)
	log.Println("Starting charcoal", version, ", establishing connection to nftables")
	connNft, err = nftables.New()
	if err != nil {
		log.Fatalln("Could not establish connection to nftables: " + err.Error())
	}
	log.Println("Established connection")

}