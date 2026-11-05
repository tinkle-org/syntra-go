package network

import (
	"context"
	"errors"

	syntra "github.com/tinkle-org/syntra-go"
	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

// RecoveryProfile retains only connection-local negotiation state. Persistence
// is explicitly application-owned and may be shared across fresh profiles.
type RecoveryProfile struct {
	*syntra.RecoveryClient
	request *pb.RecoveryNegotiateRequest
}

func (p *RecoveryProfile) Negotiate(ctx context.Context) error {
	_, err := p.RecoveryClient.Negotiate(ctx, p.request)
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) && rpc != nil && rpc.Code == syntra.ErrorCodeUnimplemented {
		return FailureRecoveryUnavailable
	}
	return err
}

// NewRecoveryFactory attaches NewRecoveryClient in the connector's preparer,
// before any Run or I/O. Negotiation is repeated for every fresh generation.
// Applications fence delivery from retained profiles using IsGenerationCurrent.
func NewRecoveryFactory(principalScope string, store syntra.RecoveryPersistence, limits syntra.RecoveryLimits, request *pb.RecoveryNegotiateRequest) (RecoveryFactory, error) {
	if store == nil || principalScope == "" || len(principalScope) > 1024 || limits.Validate() != nil || request == nil || syntra.ValidateRecovery(request) != nil {
		return nil, ErrConfig
	}
	request = proto.Clone(request).(*pb.RecoveryNegotiateRequest)
	return func(core *syntra.Client) (RecoverySession, error) {
		client, err := syntra.NewRecoveryClient(core, principalScope, store, limits)
		if err != nil {
			return nil, err
		}
		return &RecoveryProfile{RecoveryClient: client, request: proto.Clone(request).(*pb.RecoveryNegotiateRequest)}, nil
	}, nil
}
