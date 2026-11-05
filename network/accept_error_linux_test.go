package network

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcceptErrorLinuxPendingNetworkErrnos(t *testing.T) {
	checkAcceptErrnos(t, []error{unix.ENONET, unix.EPROTO, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EHOSTDOWN}, nil)
}
