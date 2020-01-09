//
// tlv.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package tlv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

var (
	bo = binary.BigEndian
)

type Type uint32

type Values map[Type]interface{}

func (v Values) Keys() []Type {
	keys := make([]Type, len(v))
	i := 0
	for key := range v {
		keys[i] = key
		i++
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	return keys
}

type VType uint8

const (
	VT_BOOL VType = iota
	VT_INT
	VT_STRING
	VT_MAP
)

var vtypes = map[VType]string{
	VT_BOOL:   "bool",
	VT_INT:    "int",
	VT_STRING: "string",
	VT_MAP:    "map",
}

func (vt VType) String() string {
	name, ok := vtypes[vt]
	if ok {
		return name
	}
	return fmt.Sprintf("{VType %d}", vt)
}

type Tag uint64

func (t Tag) Type() Type {
	return Type(t >> 3)
}

func (t *Tag) SetType(val Type) {
	*t = Tag(val)<<3 | Tag(*t&0x7)
}

func (t Tag) VType() VType {
	return VType(t & 0x7)
}

func (t *Tag) SetVType(val VType) {
	*t = Tag(*t&^0x7) | Tag(val)
}

func (t Tag) String() string {
	return fmt.Sprintf("%s: %d", t.VType(), t.Type())
}

func (v Values) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	var tmp [8]byte

	for _, key := range v.Keys() {
		var tag Tag

		tag.SetType(key)

		switch val := v[key].(type) {
		case bool:
			tag.SetVType(VT_BOOL)
			marshalInt(uint64(tag), buf)
			buf.WriteByte(1)
			if val {
				buf.WriteByte(1)
			} else {
				buf.WriteByte(0)
			}

		case uint8:
			tag.SetVType(VT_INT)
			marshalInt(uint64(tag), buf)
			buf.WriteByte(1)
			buf.WriteByte(byte(val))

		case uint16:
			tag.SetVType(VT_INT)
			marshalInt(uint64(tag), buf)
			marshalInt(2, buf)
			bo.PutUint16(tmp[:], uint16(val))
			buf.Write(tmp[:2])

		case uint32:
			tag.SetVType(VT_INT)
			marshalInt(uint64(tag), buf)
			marshalInt(4, buf)
			bo.PutUint32(tmp[:], uint32(val))
			buf.Write(tmp[:4])

		case uint64:
			tag.SetVType(VT_INT)
			marshalInt(uint64(tag), buf)
			marshalInt(8, buf)
			bo.PutUint64(tmp[:], uint64(val))
			buf.Write(tmp[:8])

		case string:
			tag.SetVType(VT_STRING)
			marshalInt(uint64(tag), buf)
			data := []byte(val)
			marshalInt(uint64(len(data)), buf)
			buf.Write(data)

		case Values:
			tag.SetVType(VT_MAP)
			marshalInt(uint64(tag), buf)
			d, err := val.Marshal()
			if err != nil {
				return nil, err
			}
			marshalInt(uint64(len(d)), buf)
			buf.Write(d)

		default:
			fmt.Printf("Type %T (val=%v) not supported\n", val, val)
		}
	}

	return buf.Bytes(), nil
}

func Unmarshal(data []byte) (Values, error) {
	result := make(Values)
	ofs := 0

	var ival, length uint64
	var err error

	for ofs < len(data) {
		ival, ofs, err = unmarshalInt(data, ofs)
		if err != nil {
			return nil, err
		}
		tag := Tag(ival)
		length, ofs, err = unmarshalInt(data, ofs)
		if err != nil {
			return nil, err
		}

		var val interface{}

		if ofs+int(length) > len(data) {
			return nil, fmt.Errorf("Truncated data")
		}

		switch tag.VType() {
		case VT_BOOL:
			if data[ofs] != 0 {
				val = true
			} else {
				val = false
			}

		case VT_INT:
			switch length {
			case 1:
				val = uint8(data[ofs])

			case 2:
				val = bo.Uint16(data[ofs:])

			case 4:
				val = bo.Uint32(data[ofs:])

			case 8:
				val = bo.Uint64(data[ofs:])

			default:
				return nil, fmt.Errorf("Invalid integer data length %d", length)
			}

		case VT_STRING:
			val = string(data[ofs : ofs+int(length)])

		case VT_MAP:
			val, err = Unmarshal(data[ofs : ofs+int(length)])
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("Invalid value type %s", tag.VType())
		}
		ofs += int(length)

		result[tag.Type()] = val
	}

	return result, nil
}

func marshalInt(val uint64, buf *bytes.Buffer) {
	mask := uint64(0x7f << 28)

	i := 4

	// Skip zero septets.
	for ; i > 0; i-- {
		masked := val & mask
		if masked != 0 {
			break
		}
		mask >>= 7
	}
	// Write value septets.
	for ; i >= 0; i-- {
		masked := val & mask
		masked >>= uint64(i * 7)
		if i > 0 {
			masked |= 0x80
		}
		buf.WriteByte(byte(masked))
		mask >>= 7
	}
}

func unmarshalInt(data []byte, ofs int) (uint64, int, error) {
	// Read max 5 bytes.
	var result uint64
	for i := 0; i < 5; i++ {
		if ofs >= len(data) {
			return 0, ofs, fmt.Errorf("Unexpected EOF")
		}
		bit := data[ofs] & 0x80
		val := data[ofs] & 0x7f

		ofs++

		result <<= 7
		result |= uint64(val)

		if bit == 0 {
			return result, ofs, nil
		}
	}
	return 0, ofs, fmt.Errorf("Unexpected EOF")
}
