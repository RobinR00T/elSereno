//go:build offensive

package s7

import (
	"testing"

	s7wire "local/elsereno/internal/protocols/s7/wire"
)

// TestAllowedWriteItem_Matches pins the per-item match
// semantics: same area + same DB (for DB/DI areas) +
// item range fits inside [AddrStart, AddrEnd].
func TestAllowedWriteItem_Matches(t *testing.T) {
	cases := []struct {
		name string
		a    AllowedWriteItem
		item s7wire.WriteItem
		want bool
	}{
		{
			name: "exact byte fit DB42",
			a:    AllowedWriteItem{Area: 0x84, DB: 42, AddrStart: 100, AddrEnd: 103},
			item: s7wire.WriteItem{Area: 0x84, DB: 42, ByteAddr: 100, Length: 4},
			want: true,
		},
		{
			name: "item start before allowlist",
			a:    AllowedWriteItem{Area: 0x84, DB: 42, AddrStart: 100, AddrEnd: 200},
			item: s7wire.WriteItem{Area: 0x84, DB: 42, ByteAddr: 99, Length: 1},
			want: false,
		},
		{
			name: "item end past allowlist",
			a:    AllowedWriteItem{Area: 0x84, DB: 42, AddrStart: 100, AddrEnd: 200},
			item: s7wire.WriteItem{Area: 0x84, DB: 42, ByteAddr: 200, Length: 4},
			want: false,
		},
		{
			name: "different DB",
			a:    AllowedWriteItem{Area: 0x84, DB: 42, AddrStart: 0, AddrEnd: 1000},
			item: s7wire.WriteItem{Area: 0x84, DB: 43, ByteAddr: 50, Length: 1},
			want: false,
		},
		{
			name: "M area DB ignored",
			a:    AllowedWriteItem{Area: 0x83, DB: 0, AddrStart: 100, AddrEnd: 200},
			item: s7wire.WriteItem{Area: 0x83, DB: 99, ByteAddr: 150, Length: 4},
			want: true,
		},
		{
			name: "different area",
			a:    AllowedWriteItem{Area: 0x84, DB: 1, AddrStart: 0, AddrEnd: 1000},
			item: s7wire.WriteItem{Area: 0x83, DB: 0, ByteAddr: 50, Length: 1},
			want: false,
		},
		{
			name: "single-byte allowlist single-byte item",
			a:    AllowedWriteItem{Area: 0x84, DB: 1, AddrStart: 50, AddrEnd: 50},
			item: s7wire.WriteItem{Area: 0x84, DB: 1, ByteAddr: 50, Length: 1},
			want: true,
		},
	}
	for _, c := range cases {
		if got := c.a.Matches(c.item); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAllowlistHash_BackcompatEmptyItems pins that an
// empty AllowedWriteItems list yields the same hash as
// pre-v1.52 SessionMutationLegacy.
func TestAllowlistHash_BackcompatEmptyItems(t *testing.T) {
	target := "10.0.0.1:102"
	allowed := []AllowedFunction{{FC: s7wire.FuncWriteVar}, {FC: s7wire.FuncPLCStop}}
	withItems := AllowlistHash(target, allowed, nil)
	legacy := SessionMutationLegacy(target, allowed).PayloadHash
	if withItems != legacy {
		t.Errorf("empty-items hash differs from legacy hash:\n%x\n%x", withItems, legacy)
	}
}

// TestAllowlistHash_DifferentItems pins that any change to
// the AllowedWriteItems list changes the hash. Operators
// editing the per-address allowlist invalidate prior
// confirm-tokens (forcing a re-mint).
func TestAllowlistHash_DifferentItems(t *testing.T) {
	target := "10.0.0.1:102"
	allowed := []AllowedFunction{{FC: s7wire.FuncWriteVar}}
	a := []AllowedWriteItem{{Area: 0x84, DB: 42, AddrStart: 0, AddrEnd: 100}}
	b := []AllowedWriteItem{{Area: 0x84, DB: 42, AddrStart: 0, AddrEnd: 200}}
	if AllowlistHash(target, allowed, a) == AllowlistHash(target, allowed, b) {
		t.Errorf("changing AddrEnd did not change hash")
	}
}

// TestAllowlistHash_OrderInsensitive pins that re-ordering
// AllowedWriteItems doesn't change the hash. Operators
// shouldn't have to think about list order.
func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	target := "10.0.0.1:102"
	allowed := []AllowedFunction{{FC: s7wire.FuncWriteVar}}
	a := []AllowedWriteItem{
		{Area: 0x84, DB: 1, AddrStart: 0, AddrEnd: 100},
		{Area: 0x83, DB: 0, AddrStart: 200, AddrEnd: 300},
	}
	b := []AllowedWriteItem{
		{Area: 0x83, DB: 0, AddrStart: 200, AddrEnd: 300},
		{Area: 0x84, DB: 1, AddrStart: 0, AddrEnd: 100},
	}
	if AllowlistHash(target, allowed, a) != AllowlistHash(target, allowed, b) {
		t.Errorf("AllowlistHash is order-sensitive")
	}
}
