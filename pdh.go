package pdh

import (
  "encoding/binary"
  "io"
  "time"

  "github.com/busoc/timutil"
)

const (
	UMICodeLen   = 6
	UMIHeaderLen = 25
)

const BufferSize = 4096

type Packet struct {
  UMIHeader
  Data []byte
}

type Decoder struct {
	inner  io.Reader
	buffer []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		inner:  r,
		buffer: make([]byte, BufferSize),
	}
}

func (d *Decoder) Decode(data bool) (p Packet, err error) {
	n, err := d.inner.Read(d.buffer)
	if err != nil {
		return
	}
	return decodePacket(d.buffer[:n], data)
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
    copy(p.Data, buffer[UMIHeaderLen:])
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
