package pdh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/busoc/timutil"
)

var (
	ErrEmpty   = errors.New("empty")
	ErrMissing = errors.New("no bytes left in buffer")
)

const (
	UMICodeLen   = 6
	UMIHeaderLen = 25
)

const BufferSize = 4096

func WithCodes(vs [][]byte) func(h UMIHeader) (bool, error) {
	return func(u UMIHeader) (bool, error) {
		for _, v := range vs {
			if len(v) != UMICodeLen {
				return false, fmt.Errorf("%x: invalid code", v)
			}
			if bytes.Equal(v, u.Code[:]) {
				return true, nil
			}
		}
		return false, nil
	}
}

func WithOrigin(o byte) func(h UMIHeader) (bool, error) {
	return func(u UMIHeader) (bool, error) {
		return (o == 0 || o == u.Code[0]), nil
	}
}

type Decoder struct {
	filter func(h UMIHeader) (bool, error)
	inner  io.Reader
	buffer []byte
}

func NewDecoder(r io.Reader, filter func(UMIHeader) (bool, error)) *Decoder {
	if filter == nil {
		filter = func(_ UMIHeader) (bool, error) {
			return true, nil
		}
	}
	return &Decoder{
		filter: filter,
		inner:  r,
		buffer: make([]byte, BufferSize),
	}
}

func (d *Decoder) Decode(data bool) (p Packet, err error) {
	var (
		keep bool
		n    int
	)
	n, err = d.inner.Read(d.buffer)
	if err != nil {
		return
	}
	p, err = decodePacket(d.buffer[:n], data)
	if err != nil {
		return
	}
	if keep, err = d.filter(p.UMIHeader); !keep {
		return d.Decode(data)
	}
	return
}

func decodePacket(buffer []byte, data bool) (p Packet, err error) {
	if len(buffer) < UMIHeaderLen {
		err = io.ErrShortBuffer
		return
	}
	if p.UMIHeader, err = decodeHeader(buffer); err != nil {
		return
	}
	if data {
		length := int(p.Len) + UMIHeaderLen
		if length > len(buffer) {
			err = io.ErrShortBuffer
			return
		}
		p.Data = make([]byte, int(p.Len))
		if n := copy(p.Data, buffer[UMIHeaderLen:]); n < len(p.Data) {
			err = ErrMissing
			return
		}
	}
	return
}

type UMIPacketState uint8

const (
	StateNoValue UMIPacketState = iota
	StateSameValue
	StateNewValue
	StateLatestValue
	StateErrorValue
)

func (u UMIPacketState) String() string {
	switch u {
	default:
		return "***"
	case StateNoValue:
		return "none"
	case StateSameValue:
		return "same"
	case StateNewValue:
		return "new"
	case StateLatestValue:
		return "latest"
	case StateErrorValue:
		return "unavailable"
	}
}

type UMIValueType uint8

const (
	Int32 UMIValueType = iota + 1
	Float64
	Binary8
	Reference
	String8
	Long
	Decimal
	Real
	Exponent
	Time
	DateTime
	StringN
	BinaryN
	Bit
)

func (u UMIValueType) String() string {
	switch u {
	default:
		return "***"
	case Int32, Long:
		return "long"
	case Float64, Real, Exponent, Decimal:
		return "double"
	case Binary8, BinaryN:
		return "binary"
	case Reference:
		return "reference"
	case String8, StringN:
		return "string"
	case DateTime, Time:
		return "time"
	case Bit:
		return "bit"
	}
}

type Packet struct {
	UMIHeader
	Data []byte
}

func (p Packet) Marshal() ([]byte, error) {
	if len(p.Data) == 0 {
		return nil, ErrEmpty
	}
	buf := make([]byte, UMIHeaderLen+int(p.Len))
	offset := copy(buf, encodeHeader(p.UMIHeader))
	copy(buf[offset:], p.Data)
	return buf, nil
}

type UMIHeader struct {
	Size   uint32
	Code   [UMICodeLen]byte
	Orbit  uint32
	State  UMIPacketState
	Type   UMIValueType
	Len    uint16
	Unit   uint16
	Coarse uint32
	Fine   uint8
}

func (u UMIHeader) Timestamp() time.Time {
	return timutil.Join5(u.Coarse, u.Fine)
}

func encodeHeader(u UMIHeader) []byte {
	buf := make([]byte, UMIHeaderLen)

	binary.LittleEndian.PutUint32(buf[0:], u.Size)
	buf[4] = byte(u.State)
	binary.BigEndian.PutUint32(buf[5:], u.Orbit)
	copy(buf[9:], u.Code[:])
	buf[15] = byte(u.Type)
	binary.BigEndian.PutUint16(buf[16:], u.Unit)
	binary.BigEndian.PutUint32(buf[18:], u.Coarse)
	buf[22] = byte(u.Fine)
	binary.BigEndian.PutUint16(buf[23:], u.Len)

	return buf
}

func decodeHeader(body []byte) (UMIHeader, error) {
	var h UMIHeader

	h.Size = binary.LittleEndian.Uint32(body[0:])
	h.State = UMIPacketState(body[4])
	h.Orbit = binary.BigEndian.Uint32(body[5:])
	copy(h.Code[:], body[9:15])
	h.Type = UMIValueType(body[15])
	h.Unit = binary.BigEndian.Uint16(body[16:])
	h.Coarse = binary.BigEndian.Uint32(body[18:])
	h.Fine = uint8(body[22])
	h.Len = binary.BigEndian.Uint16(body[23:])

	return h, nil
}
