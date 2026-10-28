package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/client"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/tests/integration/internal/fixture"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	ws "github.com/tinkle-org/syntra-go/transport/websocket"
)

const operationBound = 5 * time.Second

type suite struct {
	image      string
	proxyImage string
	network    *tc.DockerNetwork
}

func newSuite(t *testing.T) *suite {
	t.Helper()
	// Testcontainers host discovery may panic when no provider exists. Turn that
	// into an explicit test FAILURE, never a healthy-looking skipped job.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Docker provider unavailable: %v", r)
		}
	}()
	provider, err := tc.NewDockerProvider()
	if err != nil {
		t.Fatalf("Docker provider required: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if _, err := provider.Client().Ping(ctx, client.PingOptions{}); err != nil {
		t.Fatalf("Docker daemon required: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	buildImage := func(target string) string {
		var buildLog cappedLog
		t.Cleanup(func() { artifact(t, target+"-build.log", buildLog.Bytes()) })
		image, err := provider.BuildImage(ctx, &tc.ContainerRequest{FromDockerfile: tc.FromDockerfile{
			Context: root, Dockerfile: "tests/integration/Dockerfile", BuildLogWriter: &buildLog,
			BuildOptionsModifier: func(opts *client.ImageBuildOptions) { opts.Target = target },
		}})
		if err != nil {
			t.Fatalf("build %s fixture: %v\n%s", target, err, buildLog.Bytes())
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := provider.Client().ImageRemove(ctx, image, client.ImageRemoveOptions{Force: true, PruneChildren: true}); err != nil {
				t.Errorf("remove %s fixture image: %v", target, err)
			}
		})
		return image
	}
	image, proxyImage := buildImage("peer"), buildImage("toxiproxy")
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := nw.Remove(ctx); err != nil {
			t.Errorf("remove test network: %v", err)
		}
	})
	return &suite{image: image, proxyImage: proxyImage, network: nw}
}

type peer struct {
	container tc.Container
	config    fixture.Config // immutable; every negative case mutates a value copy
	address   string
	alias     string
	tls       *tls.Config
}

func (s *suite) startPeer(t *testing.T, cfg fixture.Config, alias string) *peer {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("encode test provisioning")
	}
	files := []tc.ContainerFile{{Reader: bytes.NewReader(data), ContainerFilePath: "/provision.json", FileMode: 0o400}}
	p := &peer{config: cfg, alias: alias}
	if cfg.Protocol == "wss" {
		cert, key, roots := testCertificate(t)
		files = append(files,
			tc.ContainerFile{Reader: bytes.NewReader(cert), ContainerFilePath: "/server.pem", FileMode: 0o400},
			tc.ContainerFile{Reader: bytes.NewReader(key), ContainerFilePath: "/server-key.pem", FileMode: 0o400},
		)
		p.tls = &tls.Config{RootCAs: roots, ServerName: fixture.TLSName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := tc.Run(ctx, s.image,
		tc.WithExposedPorts("8080/tcp"), tc.WithFiles(files...),
		network.WithNetwork([]string{alias}, s.network),
		tc.WithWaitStrategy(wait.ForLog(`"msg":"listener_bound"`).WithStartupTimeout(30*time.Second)),
	)
	if c != nil {
		cleanupContainer(t, c)
	}
	if err != nil {
		t.Fatalf("start %s/%s peer: %v", cfg.Protocol, cfg.Mode, err)
	}
	p.container = c
	p.address = mappedAddress(t, ctx, c, "8080/tcp")
	// A structured bound-listener log is necessary but insufficient: require
	// Noise M1/M2, confirmed ClientHello policy, ServerReady and an actual RPC.
	probe := p.connect(t)
	echo(t, probe.client, []byte("readiness"))
	probe.close(t)
	return p
}

func mappedAddress(t *testing.T, ctx context.Context, c tc.Container, port string) string {
	t.Helper()
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := c.MappedPort(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, mapped.Port())
}

func (p *peer) dial(ctx context.Context, cfg securechannel.ClientConfig, tlsConfig *tls.Config) (*ordered.Transport, error) {
	limits := ordered.Options{HandshakeTimeout: 3 * time.Second, WriteTimeout: 2 * time.Second}
	if p.config.Protocol == "tcp" {
		return tcp.Dial(ctx, p.address, cfg, limits)
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	return ws.Dial(ctx, p.config.Protocol+"://"+p.address+"/sc1", cfg, ws.Options{Limits: limits, HTTPClient: &http.Client{Transport: tr}})
}

type session struct {
	client    *syntra.Client
	transport *ordered.Transport
	cancel    context.CancelFunc
	done      chan struct{}
	runErr    error // published by closing done
	once      sync.Once
}

func (p *peer) connect(t *testing.T) *session {
	t.Helper()
	return p.connectCredential(t, p.config.HelloCredential())
}

func (p *peer) connectCredential(t *testing.T, credential []byte) *session {
	t.Helper()
	cfg, err := p.config.Client()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	tr, err := p.dial(ctx, cfg, p.tls)
	if err != nil {
		t.Fatalf("SC1 dial: %v", err)
	}
	c, err := syntra.OpenClient(syntra.ClientConfig{Credential: credential, DefaultTimeout: 20 * time.Second})
	if err != nil {
		_ = tr.Close()
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	s := &session{client: c, transport: tr, cancel: stop, done: make(chan struct{})}
	go func() { defer close(s.done); s.runErr = c.Run(runCtx, tr) }()
	t.Cleanup(func() { s.close(t) })
	return s
}

func (s *session) close(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		s.cancel()
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = s.client.Close()
			_ = s.transport.Close()
		}()
		timer := time.NewTimer(operationBound)
		defer timer.Stop()
		for _, done := range []<-chan struct{}{closed, s.done} {
			select {
			case <-done:
			case <-timer.C:
				t.Error("client Close/Run did not stop within 5s")
				return
			}
		}
	})
}

func echo(t *testing.T, c *syntra.Client, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	got, err := c.Call(ctx, fixture.EchoMethod, payload, 5000)
	if err != nil {
		t.Fatalf("echo (%d bytes): %v", len(payload), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo differs (%d bytes)", len(payload))
	}
}

func wantCode(t *testing.T, err error, code syntra.ErrorCode) {
	t.Helper()
	var rpc *syntra.RpcError
	if !errors.As(err, &rpc) || rpc.Code != code {
		t.Fatalf("want %s, got %v", syntra.ErrorCodeName(code), err)
	}
}

func awaitError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(operationBound):
		t.Fatal("pending call did not complete within 5s")
		return nil
	}
}

func (p *peer) waitEvent(t *testing.T, event string, token uint64) {
	t.Helper()
	// slog JSON keeps msg and token adjacent; match both so prior calls cannot
	// satisfy a later cancellation/shutdown observation.
	needle := fmt.Sprintf(`"msg":%q,"token":%d}`, event, token)
	p.waitLog(t, needle)
}

func (p *peer) waitLog(t *testing.T, needle string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	if err := wait.ForLog(needle).WithStartupTimeout(operationBound).WaitUntilReady(ctx, p.container); err != nil {
		t.Fatalf("wait for fixture event %s: %v", needle, err)
	}
}

func testCertificate(t *testing.T) (certPEM, keyPEM []byte, pool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Syntra integration CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), DNSNames: []string{fixture.TLSName}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("invalid test CA")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pool
}

// Build/container logs are bounded independently of test runtime. Provisioning
// files and TLS material are never artifacts; the fixture logs only events.
type cappedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *cappedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if remaining := (128 << 10) - b.buf.Len(); remaining > 0 {
		_, _ = b.buf.Write(p[:min(remaining, n)])
	}
	return n, nil
}
func (b *cappedLog) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

func artifact(t *testing.T, suffix string, data []byte) {
	t.Helper()
	dir := os.Getenv("SYNTRA_INTEGRATION_LOG_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Errorf("create log directory: %v", err)
		return
	}
	name := strings.NewReplacer("/", "-", "\\", "-").Replace(t.Name()) + "-" + suffix
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Errorf("write bounded log: %v", err)
	}
}

func cleanupContainer(t *testing.T, c tc.Container) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		logs, err := c.Logs(ctx)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(logs, 64<<10))
			_ = logs.Close()
			if readErr == nil {
				artifact(t, "container.log", data)
			}
		}
		if err := c.Terminate(ctx); err != nil {
			t.Errorf("terminate container: %v", err)
		}
	})
}
