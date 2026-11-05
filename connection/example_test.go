package connection_test

import (
	"context"
	"fmt"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
)

func ExampleConnect() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientSecurity, hostSecurity, err := channelConfigs(securechannel.Bootstrap)
	if err != nil {
		panic(err)
	}
	// Construct each budget before carrier setup. A real embedder uses its
	// Budget.Context(ctx) during setup and supplies the resulting MessageIO.
	clientOptions, hostOptions := testOptions(), testOptions()
	initiator, responder := recordPair()
	host, err := syntra.OpenHost(syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			// Bootstrap proves channel participation; the credential must
			// independently authorize the application principal.
			if id.Mode != "bootstrap" || id.Scope != "memory" || string(credential) != "application-credential" {
				return "", syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "denied")
			}
			return "operator", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(request.GetPayload()), nil
		},
	})
	if err != nil {
		panic(err)
	}
	defer host.Close()
	accepted := make(chan error, 1)
	go func() { accepted <- connection.Accept(ctx, responder, hostSecurity, host, hostOptions) }()
	client, err := connection.Connect(ctx, initiator, clientSecurity,
		syntra.ClientConfig{Credential: []byte("application-credential")}, clientOptions)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	echo, err := client.Call(ctx, "/example.Echo/Echo", []byte("hello"), 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(echo))
	if err := host.NotifyAll([]byte("updated")); err != nil {
		panic(err)
	}
	select {
	case notification := <-client.Notifications():
		fmt.Println(string(notification.GetPayload()))
	case <-ctx.Done():
		panic(ctx.Err())
	}
	if err := client.Close(); err != nil {
		panic(err)
	}
	<-accepted // Accept joins this carrier; Host remains caller-owned.
	// Output:
	// hello
	// updated
}

func ExampleServer_Accept() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientSecurity, hostSecurity, err := channelConfigs(securechannel.Returning)
	if err != nil {
		panic(err)
	}
	server, err := connection.NewServer(syntra.HostConfig{
		ChannelPolicy: func(_ context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if id.Principal != "device" || string(credential) != "application-credential" {
				return "", syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "denied")
			}
			return "operator", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(request.GetPayload()), nil
		},
	}, hostSecurity, connection.ServerOptions{MaxConnections: 8})
	if err != nil {
		panic(err)
	}
	defer server.Close()
	clientOptions, hostOptions := testOptions(), testOptions()
	initiator, responder := recordPair()
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(ctx, responder, hostOptions) }()
	client, err := connection.Connect(ctx, initiator, clientSecurity,
		syntra.ClientConfig{Credential: []byte("application-credential")}, clientOptions)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	echo, err := client.Call(ctx, "/example.Echo/Echo", []byte("ready"), 0)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(echo))
	if err := server.Close(); err != nil {
		panic(err)
	}
	<-accepted
	<-server.Done()
	// Output: ready
}
