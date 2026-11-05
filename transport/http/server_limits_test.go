package syntrahttp

import (
	"errors"
	"strconv"
	"testing"

	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestServerLimitsDefaultHandshakesWithinAssociations(t *testing.T) {
	for associations := 0; associations <= 33; associations++ {
		t.Run(strconv.Itoa(associations), func(t *testing.T) {
			limits, err := (ServerLimits{Associations: associations}).normalize()
			if err != nil {
				t.Fatal(err)
			}
			want := 32
			if associations != 0 {
				want = min(want, associations)
			}
			if limits.Handshakes != want {
				t.Fatalf("default handshakes = %d, want %d", limits.Handshakes, want)
			}
			if again, err := limits.normalize(); err != nil || again != limits {
				t.Fatalf("normalized limits changed: %+v, %v", again, err)
			}
		})
	}
}

func TestServerLimitsExplicitHandshakesValidation(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		associations, handshakes int
		invalid                  bool
	}{
		{"equal_small", 1, 1, false},
		{"below_small", 31, 7, false},
		{"above_default", 64, 48, false},
		{"above_small", 1, 2, true},
		{"above_31", 31, 32, true},
		{"above_large", 64, 65, true},
		{"above_default_associations", 0, 129, true},
		{"negative", 1, -1, true},
		{"out_of_range", 65536, 65537, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits, err := (ServerLimits{Associations: tc.associations, Handshakes: tc.handshakes}).normalize()
			if tc.invalid {
				if !errors.Is(err, ordered.ErrOptions) {
					t.Fatalf("invalid explicit limit accepted: %+v, %v", limits, err)
				}
			} else if err != nil || limits.Handshakes != tc.handshakes {
				t.Fatalf("explicit limit changed: %+v, %v", limits, err)
			}
		})
	}
}
