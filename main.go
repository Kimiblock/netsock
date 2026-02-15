package main

import (
	//"fmt"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	//"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"context"
	"github.com/Kimiblock/pecho"
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
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
	appID			string
	appGPath		string
}

type ResponseSignal struct {
	Success			bool
	Log			string
}

// Incoming signal for socket
type IncomingSig struct {
	CgroupNested		string
	RawDenyList		[]string
	SandboxEng		string
	AppID			string
}

type peerCreds struct {
	UID			uint
	GID			uint
	PID			uint
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
						continue
					}
					for _, addr := range addrs {
						tryRes := net.ParseIP(addr)
						if tryRes == nil {
							continue
						}
						tryResV4 := tryRes.To4()
						switch tryResV4 {
							case nil:
								v6DenyList = append(
									v6DenyList,
									tryRes.String(),
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

	builder.WriteString("chain netsock {\n")
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
func setAppPerms(outperm appOutPerms, sandboxEng string) bool {
	logChan <- []string{
		"debug",
		"Got firewall rules for " + outperm.appID + " from " + sandboxEng,
	}
	var table = nftables.Table {
		Name:	sandboxEng + "-" + outperm.appID,
		Family:	unix.NFPROTO_INET,
	}
	tableExt, errList := connNft.ListTableOfFamily(
		sandboxEng + "-" + outperm.appID,
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

	nftFile := buildNftFile(sandboxEng + "-" + outperm.appID, outperm)
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

func sendResponse (writer http.ResponseWriter, response ResponseSignal) {
	jsonObj, err := json.Marshal(response)
	if err != nil {
		echo("warn", "Could not marshal response, falling back to standard response")
		var respFallback ResponseSignal
		respFallback.Success = false
		respFallback.Log = "Could not marshal original response"
		jsonObj, _ := json.Marshal(respFallback)
		writer.Write(jsonObj)
		return
	}

	writer.Header().Add("Content-Type", "application/json")
	writer.Write(jsonObj)
}

func addReqHandler (writer http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	var resp ResponseSignal
	cred := request.Context().Value(peerCreds{}).(peerCreds)
	uid := cred.UID
	echo("debug", "Got an add request from user " + strconv.Itoa(int(uid)))

	var requestJson IncomingSig
	rawReq, err := io.ReadAll(request.Body)
	if err != nil {
		echo("warn", "Could not read request: " + err.Error())
		resp.Log = "Could not read request: " + err.Error()
		sendResponse(writer, resp)
		return
	}

	err = json.Unmarshal(rawReq, &requestJson)
	if err != nil {
		echo("warn", "Could not read malformed request: " + err.Error())
		resp.Log = "Could not read malformed request: " + err.Error()
		sendResponse(writer, resp)
		return
	}

	var info appOutPerms


	var invalid bool
	if len(requestJson.AppID) == 0 {
		echo("warn", "Invalid request: empty field")
		invalid = true
	} else if len(requestJson.CgroupNested) == 0 {
		echo("warn", "Invalid request: empty field")
		invalid = true
	} else if len(requestJson.SandboxEng) == 0 {
		echo("warn", "Invalid request: empty field")
		invalid = true
	// TODO: if we add allow listing, this must be modified
	// TODO: we must add rules clearing below
	} else if len(requestJson.RawDenyList) == 0 {
		echo("info", "Nothing to reject")
		resp.Success = true
		resp.Log = "Nothing to do"
		sendResponse(writer, resp)
		return
	}
	if invalid == true {
		resp.Success = false
		resp.Log = "Invalid request: empty field"
		sendResponse(writer, resp)
		return
	}

	info.denyIP = requestJson.RawDenyList
	info.appID = requestJson.AppID

	pathTemp := []string{
		"/user.slice/user-1011.slice/user@1011.service/",
		requestJson.CgroupNested,
	}

	pathG := strings.Join(
		pathTemp,
		"",
	)

	info.appGPath = strings.ReplaceAll(pathG, "//", "/")

	opRes := setAppPerms(info, requestJson.SandboxEng)

	if opRes != true {
		echo("warn", "Could not engage firewall on " + info.appID)
		resp.Success = false
		resp.Log = "Could not engage firewall on " + info.appID
	} else {
		resp.Success = true
	}

	sendResponse(writer, resp)
}

func unknownReqHandler (writer http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	var resp ResponseSignal
	resp.Success = false
	resp.Log = "Unknown operation"
	cred := request.Context().Value(peerCreds{}).(peerCreds)
	uid := cred.UID
	echo("warn", "Got an unknown request from UID: " + strconv.Itoa(int(uid)))

	sendResponse(writer, resp)
}

func shutdownWorker (shutdownChan chan os.Signal, listener net.Listener, block chan int) {
	sig := <- shutdownChan
	echo("info", "Shutting down netsock on signal " + sig.String())
	connNft.CloseLasting()
	if listener != nil {
		listener.Close()
	}
	close(block)
	close(logChan)
}

func signalListener (listener net.Listener) {
	runtimeDir := os.Getenv("RUNTIME_DIRECTORY")
	if len(runtimeDir) == 0 {
		echo("debug", "Could not read RUNTIME_DIRECTORY from environment")
		runtimeDir = "/run/netsock"
	}

	if runtimeDir != "/run/netsock" {
		echo("warn", "You have changed the runtime directory. Downstream apps may not support this.")
	}
	sockPath := filepath.Join(runtimeDir, "control.sock")
	listener, err = net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalln("Could not listen UNIX socket: " + err.Error())
		return
	}
	err = os.Chmod(sockPath, 0722)
	if err != nil {
		log.Fatalln("Could not listen UNIX socket: " + err.Error())
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", unknownReqHandler)
	mux.HandleFunc("/add", addReqHandler)

	server := http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			unixconn, ok := c.(*net.UnixConn)
			if !ok {
				echo("warn", "Could not get credentials: connection error")
				return ctx
			}
			raw, err := unixconn.SyscallConn()
			if err != nil {
				echo("warn", "Could not get credentials: " + err.Error())
			}

			var creds *syscall.Ucred
			raw.Control(func(fd uintptr) {
				creds, err = syscall.GetsockoptUcred(
					int(fd),
					syscall.SOL_SOCKET,
					syscall.SO_PEERCRED,
				)
				if err != nil {
					echo("warn", "Getsockopt failed: " + err.Error())
				}
			})
			if ctx == nil {
				return ctx
			}
			peerCred := peerCreds {
				UID:	uint(creds.Uid),
				GID:	uint(creds.Gid),
				PID:	uint(creds.Pid),
			}
			return context.WithValue(ctx, peerCreds{}, peerCred)
		},
		Handler: mux,
	}


	http.HandleFunc("/", unknownReqHandler)
	server.Serve(listener)
}

func main() {
	var unixListener net.Listener
	sigChan := make(chan os.Signal, 1)
	blockerChan := make(chan int, 1)
	go shutdownWorker(sigChan, unixListener, blockerChan)
	go signalListener(unixListener)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	go pecho.StartDaemon(logChan)
	log.Println("Starting netsock", version, ", establishing connection to nftables")
	connNft, err = nftables.New()
	if err != nil {
		log.Fatalln("Could not establish connection to nftables: " + err.Error())
	}
	echo("debug", "Established connection to nftables netlink socket")


	<- blockerChan

}