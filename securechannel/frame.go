package securechannel

import "encoding/binary"

// FramePlaintext prefixes a nonempty frame with its encrypted stream length.
// Split the returned bytes into records no larger than MaxPlaintext.
func FramePlaintext(frame []byte) ([]byte, error) {
	if len(frame) == 0 || len(frame) > MaxFrame {
		return nil, ErrLimit
	}
	out := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(out, uint32(len(frame)))
	copy(out[4:], frame)
	return out, nil
}

// FrameDecoder incrementally parses authenticated plaintext with at most one
// incomplete frame. Its zero value is ready for use; any error is terminal.
type FrameDecoder struct {
	prefix    [4]byte
	prefixLen int
	body      []byte
	expected  int
	failed    bool
}

func (d *FrameDecoder) IsPartial() bool { return d.prefixLen != 0 || d.expected != 0 }

func (d *FrameDecoder) Close() {
	clear(d.prefix[:])
	clear(d.body)
	d.body = nil
	d.prefixLen, d.expected, d.failed = 0, 0, true
}

func (d *FrameDecoder) Push(input []byte) ([][]byte, error) {
	if d.failed {
		return nil, ErrClosed
	}
	if len(input) > MaxPlaintext {
		d.Close()
		return nil, ErrLimit
	}
	var frames [][]byte
	for len(input) != 0 {
		if d.expected == 0 {
			n := copy(d.prefix[d.prefixLen:], input)
			d.prefixLen += n
			input = input[n:]
			if d.prefixLen != 4 {
				break
			}
			next := binary.BigEndian.Uint32(d.prefix[:])
			if next == 0 || next > MaxFrame {
				for _, frame := range frames {
					clear(frame)
				}
				d.Close()
				return nil, ErrLimit
			}
			d.expected, d.prefixLen = int(next), 0
			d.body = make([]byte, 0, d.expected)
		}
		n := min(d.expected-len(d.body), len(input))
		d.body = append(d.body, input[:n]...)
		input = input[n:]
		if len(d.body) == d.expected {
			frames = append(frames, d.body)
			d.body, d.expected = nil, 0
		}
	}
	return frames, nil
}
