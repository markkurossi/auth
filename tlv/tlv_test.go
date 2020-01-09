//
// tlv.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package tlv

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestTags(t *testing.T) {
	key := uint32(1 << 31)
	for i := 0; i <= 32; i++ {
		values := Values{
			Type(key): key,
		}
		data, err := values.Marshal()
		if err != nil {
			t.Fatalf("Marshal type %d failed: %s\n", key, err)
		}
		if false {
			fmt.Printf("Encoded:\n%s", hex.Dump(data))
		}

		decoded, err := Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal type %d failed: %s\n", key, err)
		}
		val, ok := decoded[Type(key)]
		if !ok {
			t.Fatalf("Decoded values does not contain key")
		}
		ival, ok := val.(uint32)
		if !ok {
			t.Fatalf("Invalid value type %T", val)
		}
		if ival != key {
			t.Fatalf("Invalid value: got %d, expected %d", ival, key)
		}

		key >>= 1
	}
}

func TestMarshal(t *testing.T) {
	values := Values{
		Type(0): uint8(8),
		Type(1): uint16(16),
		Type(2): uint32(32),
		Type(3): uint64(64),
		Type(4): "foo",
		Type(5): Values{
			Type(3): uint32(0),
		},
		Type(6): true,
		Type(7): false,
	}

	data, err := values.Marshal()
	if err != nil {
		t.Errorf("Marshal failed: %s\n", err)
	}
	fmt.Printf("Data:\n%s", hex.Dump(data))

	decoded, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s\n", err)
	}
	fmt.Printf("Decoded: %v\n", decoded)

	for k, v := range values {
		dval, ok := decoded[k]
		if !ok {
			t.Fatalf("Decoded does not contain key %v\n", k)
		}
		switch eval := v.(type) {
		case Values:
			deval, ok := dval.(Values)
			if !ok {
				t.Fatalf("Failed: %v, %v\n", eval, deval)
			}

		default:
			if v != dval {
				t.Fatalf("Value mismatch: got %v, expected %v\n", dval, v)
			}
		}
	}
}
