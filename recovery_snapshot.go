package syntra

import (
	"bytes"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

// StageChunk checks the typed chunk's handle as well as its index and boundary.
func (s *StagedSnapshot) StageChunk(chunk *pb.RecoverySnapshotChunk) error {
	if s == nil {
		return recoveryInvalid()
	}
	if err := ValidateRecovery(chunk); err != nil {
		return err
	}
	if !bytes.Equal(chunk.SnapshotHandle, s.handle) {
		return recoveryInvalid()
	}
	return s.StagePage(int(chunk.PageIndex), chunk.PageBytes, chunk.BoundaryCheckpoint)
}

// Completion is a local transfer record, never a wire notification or proof of
// persistence. It avoids assembling another copy merely to check completeness.
func (s *StagedSnapshot) Completion() (*pb.RecoverySnapshotComplete, error) {
	if s == nil {
		return nil, recoveryInvalid()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var total uint64
	for index, filled := range s.filled {
		if !filled {
			return nil, recoveryInvalid()
		}
		total += uint64(len(s.pages[index]))
	}
	return &pb.RecoverySnapshotComplete{ProfileVersion: 1, SnapshotHandle: bytes.Clone(s.handle), BoundaryCheckpoint: bytes.Clone(s.boundary), TotalPages: uint32(s.total), TotalBytes: total}, nil
}
