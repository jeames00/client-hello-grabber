package main

import (
	"encoding/json"
	"flag"
	"fmt"
	. "github.com/bradleyfalzon/tlsx"
	"github.com/caddyserver/certmagic"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var portHelloMap map[int]MyClientHello

func main() {
	c := make(chan []byte)
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = os.Getenv("CERTMAGIC_EMAIL")

	portHelloMap = make(map[int]MyClientHello)

	go packCap()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		joinMaps()
		w.Header().Add("Content-Type", "text/plain")
		go WriteRequestInfo(r.RemoteAddr, r.UserAgent(), r.Header, c)
		var jsonBytes = <-c
		io.WriteString(w, string(jsonBytes))
	})

	email := os.Getenv("CERTMAGIC_EMAIL")
	domain := os.Getenv("CERTMAGIC_DOMAIN")
	if email != "" && domain != "" {
		switch env := os.Getenv("ENVIRONMENT"); env == "STAGING" {
		case true:
			log.Println("Staring HTTPS server using *STAGING* Certmagic certificate. Rate limits DO NOT apply.")
			certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		case false:
			log.Println("Staring HTTPS server using *PRODUCTION* Certmagic certificate. Rate limits apply.")
		}
		certmagic.DefaultACME.Email = email
		log.Fatal(certmagic.HTTPS([]string{domain}, mux))
	} else {
		errs := make(chan error)

		log.Println("Starting HTTPS server with generic certificate...")
		server := &http.Server{
			Addr:         ":https",
			Handler:      mux,
			TLSNextProto: nil,
		}
		if err := server.ListenAndServeTLS("/root/server.crt", "/root/server.key"); err != nil {
			errs <- err
		}

		log.Println(errs)
		return
	}
}

func WriteRequestInfo(remoteAddr, useragent string, headers map[string][]string, c chan []byte) {
	log.Printf("request: %s - %s", remoteAddr, useragent)
	srcPort, _ := strconv.Atoi(strings.Split(remoteAddr, ":")[1])
	if helloPkt, ok := portHelloMap[srcPort]; ok {
		helloPkt.Headers = headers
		useragent = strings.ReplaceAll(useragent, " ", "_")
		useragent = strings.ReplaceAll(useragent, "/", "|")

		var jsonData []byte
		jsonData, err := json.MarshalIndent(NewJsonHello(&helloPkt), "", "\t")
		if err != nil {
			log.Println(err)
		}

		f, _ := os.OpenFile("/root/hellos/"+useragent, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		defer f.Close()
		_, _ = f.Write([]byte(jsonData))
		f.Sync()

		c <- jsonData
	}
}

func packCap() {
	iface := flag.String("iface", "eth0", "Network interface to capture on")
	flag.Parse()

	handle, err := pcap.OpenLive(*iface, 1500, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("(dst port 443)")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Listening on", *iface)
	for packet := range packetSource.Packets() {
		go readPacket(packet)
	}
}

func readPacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return
		}
		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet
			readData(packet)
		}
	}
}

func readData(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		log.Printf("Client hello from %s:%d to %s", ip4.SrcIP, t.SrcPort, t.DstPort)

		var hello = MyClientHello{}

		err := hello.Unmarshall(t.LayerPayload())

		switch err {
		case nil:
		case ErrHandshakeWrongType:
			return
		default:
			log.Println("Error reading Client Hello:", err)
			log.Println("Raw Client Hello:", t.LayerPayload())
			return
		}
		portHelloMap[int(t.SrcPort)] = hello
	} else {
		log.Println("Client Hello Reader could not decode TCP layer")
		return
	}
}
