package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
)

// opcuahttps-sim is a throwaway OPC UA HTTPS stand-in for the
// fingerprint demo (scripts/demo-opcua-https-fingerprint.sh). It is NOT
// a real OPC UA server: it serves a fixed GetEndpointsResponse over TLS
// (a self-signed cert generated at start-up) to any POST, so `elsereno
// fingerprint probe` on port 4843 exercises the opcuahttps plugin's GetEndpoints path. One of the
// advertised endpoints is SecurityMode=None, so the finding carries the
// exposure bump.
func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("addr", "127.0.0.1:4843", "listen address (TLS)")
	flag.Parse()

	cert, err := selfSignedCert()
	if err != nil {
		log.Println("opcuahttps-sim: cert:", err)
		return 1
	}

	body := wire.EncodeGetEndpointsResponse([]wire.EndpointDescription{
		{
			EndpointURL: "opc.https://sim:4843/UA", ApplicationURI: "urn:sim:UA",
			ProductURI: "urn:sim:product", ApplicationName: "ElSerenoSim",
			SecurityMode:        wire.SecurityModeSignAndEncrypt,
			SecurityPolicyURI:   "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
			TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/https-uabinary",
			SecurityLevel:       3,
		},
		{
			EndpointURL: "opc.https://sim:4843/None", ApplicationURI: "urn:sim:UA",
			ProductURI: "urn:sim:product", ApplicationName: "ElSerenoSim",
			SecurityMode:        wire.SecurityModeNone,
			SecurityPolicyURI:   "http://opcfoundation.org/UA/SecurityPolicy#None",
			TransportProfileURI: "http://opcfoundation.org/UA-Profile/Transport/https-uabinary",
			SecurityLevel:       0,
		},
	})

	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		}),
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("opcuahttps-sim: listen:", err)
		return 1
	}
	log.Printf("opcuahttps-sim: serving GetEndpoints over TLS on %s", *addr)

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ServeTLS(ln, "", ""); err != nil && ctx.Err() == nil {
		log.Println("opcuahttps-sim: serve:", err)
		return 1
	}
	return 0
}

// selfSignedCert generates an in-memory self-signed cert. The demo
// client (elsereno) fingerprints untrusted hosts and does not verify
// the peer, so the cert is throwaway.
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "elsereno-opcua-https-sim"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
