//go:build syntranative

package syntra

// decodeResultFrame validates native-owned result bytes. Missing outcomes fail;
// unknown error codes are normalized by the shared codec.
func decodeResultFrame(raw []byte) (*RpcResult, error) {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return nil, err
	}
	if BodyKindOf(f) != BodyKindResult {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: expected result frame")
	}
	res := f.GetResult()
	if err := ValidateResult(res); err != nil {
		return nil, err
	}
	return res, nil
}

func decodeNotificationFrame(raw []byte) (*Notification, error) {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return nil, err
	}
	if BodyKindOf(f) != BodyKindNotification || f.GetNotification() == nil {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: expected notification frame")
	}
	return f.GetNotification(), nil
}
