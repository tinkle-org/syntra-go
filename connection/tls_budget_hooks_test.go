package connection_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func hookTLSProvider(t *testing.T) tlsstream.Provider {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	p, err := tlsstream.NewStandardProvider(&tls.Config{RootCAs: roots}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTLSActiveIOOutlivesSharedSetupCutoff(t *testing.T) {
	p := hookTLSProvider(t)
	authority, err := tlsstream.NewAuthority("localhost", 443)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	host, err := syntra.OpenHost(hostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	co, clientAge := clockOptions(t)
	so, serverAge := clockOptions(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	accepted := make(chan error, 1)
	go func() {
		proof, err := tlsstream.Accept(context.Background(), b, p, authority, so.Budget)
		if err != nil {
			accepted <- err
			return
		}
		defer proof.Close()
		raw, err := proof.Consume(authority, tlsstream.Server, so.Budget)
		if err == nil {
			err = connection.Accept(context.Background(), tcp.New(raw, so.Budget), sc, host, so)
		}
		accepted <- err
	}()
	proof, err := tlsstream.Connect(context.Background(), a, p, authority, co.Budget)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Close()
	raw, err := proof.Consume(authority, tlsstream.Client, co.Budget)
	if err != nil {
		t.Fatal(err)
	}
	client, err := connection.Connect(context.Background(), tcp.New(raw, co.Budget), cc, syntra.ClientConfig{Credential: []byte("explicit")}, co)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	echo(t, client)
	clientAge.Store(int64(2 * time.Second))
	serverAge.Store(int64(2 * time.Second))
	echo(t, client)
	time.Sleep(30 * time.Millisecond)
	echo(t, client)
	_ = client.Close()
	join(t, accepted)
}
