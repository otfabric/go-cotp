// SPDX-License-Identifier: MIT

package cotp

// TPDUType is the X.224 TPDU type code (high bits of octet 2).
// Low bits carry CDT/options for some types (e.g. CR, CC, DT).
type TPDUType uint8

const (
	TypeCR TPDUType = 0xE0 // Connection Request (1110 xxxx)
	TypeCC TPDUType = 0xD0 // Connection Confirm (1101 xxxx)
	TypeDR TPDUType = 0x80 // Disconnect Request (1000 0000)
	TypeDC TPDUType = 0xC0 // Disconnect Confirm (1100 0000)
	TypeDT TPDUType = 0xF0 // Data (1111 000y)
	TypeER TPDUType = 0x70 // TPDU Error (0111 0000)
	TypeED TPDUType = 0x10 // Expedited Data (0001 0000)
	TypeAK TPDUType = 0x60 // Acknowledge (0110 zzzz)
	TypeEA TPDUType = 0x20 // Expedited Acknowledge (0010 0000)
	TypeRJ TPDUType = 0x50 // Reject (0101 zzzz)
)

// String returns the TPDU type name for debugging and logging.
func (t TPDUType) String() string {
	switch t {
	case TypeCR:
		return "CR"
	case TypeCC:
		return "CC"
	case TypeDR:
		return "DR"
	case TypeDC:
		return "DC"
	case TypeDT:
		return "DT"
	case TypeER:
		return "ER"
	case TypeED:
		return "ED"
	case TypeAK:
		return "AK"
	case TypeEA:
		return "EA"
	case TypeRJ:
		return "RJ"
	default:
		return "unknown"
	}
}

// MinHeaderLength is the minimum TPDU header size: LI (1) + type code (1).
const MinHeaderLength = 2

// MaxLI is the maximum length indicator value (X.224); 255 is reserved.
const MaxLI = 254

// Parameter is a single variable-part parameter (code + value).
// Value may alias the decode input; see package doc.
type Parameter struct {
	Code  uint8
	Value []byte
}

// CR is a Connection Request TPDU (X.224 13.3).
// Nil selector = absent; non-nil empty slice = present with length 0. TPDUSize nil = parameter absent.
type CR struct {
	CDT             uint8
	DestinationRef  uint16
	SourceRef       uint16
	ClassOption     uint8
	Parameters      []Parameter
	CallingSelector []byte
	CalledSelector  []byte
	TPDUSize        *uint8
}

// CC is a Connection Confirm TPDU (X.224 13.4).
// Same nil/empty semantics as CR.
type CC struct {
	CDT             uint8
	DestinationRef  uint16
	SourceRef       uint16
	ClassOption     uint8
	Parameters      []Parameter
	CallingSelector []byte
	CalledSelector  []byte
	TPDUSize        *uint8
}

// DT is a Data TPDU (X.224 13.7). v1 supports minimal (class 0/1) and normal (class 2–4) formats.
// Nil UserData or zero-length = valid empty payload. Nil DestinationRef/TPDUNR = absent (e.g. minimal format).
// UserData may alias decode input; see package doc.
type DT struct {
	EOT            bool
	TPDUNR         *uint8
	DestinationRef *uint16
	Parameters     []Parameter
	UserData       []byte
}

// Decoded is the result of Decode or DecodeWithRaw. Exactly one of CR, CC, DT, DR, DC, ER, ED, AK, EA, RJ is non-nil; Type matches it.
// Zero value is not a valid decoded result.
//
// Raw is populated only by DecodeWithRaw. When non-nil, it is the exact slice passed to DecodeWithRaw and may alias the input.
// Callers must copy if retaining or mutating beyond the lifetime of that input.
type Decoded struct {
	Type TPDUType
	CR   *CR
	CC   *CC
	DT   *DT
	DR   *DR
	DC   *DC
	ER   *ER
	ED   *ED
	AK   *AK
	EA   *EA
	RJ   *RJ
	// Raw is set only by DecodeWithRaw to the exact input slice (may alias). Nil when using Decode or on error.
	Raw []byte
}

// DR is a Disconnect Request TPDU (X.224 13.5). UserData may alias decode input.
type DR struct {
	DestinationRef uint16
	SourceRef      uint16
	Reason         uint8
	Parameters     []Parameter
	UserData       []byte
}

// DC is a Disconnect Confirm TPDU (X.224 13.6).
type DC struct {
	DestinationRef uint16
	SourceRef      uint16
	Parameters     []Parameter
}

// ER is a TPDU Error (X.224 13.12).
type ER struct {
	DestinationRef uint16
	RejectCause    uint8
	Parameters     []Parameter
}

// ED is Expedited Data (X.224 13.8). TPDUNR is the 7-bit sequence number; EOT is separate. UserData 1–16 octets.
type ED struct {
	DestinationRef *uint16
	TPDUNR         *uint8
	EOT            bool
	Parameters     []Parameter
	UserData       []byte
}

// AK is Acknowledge (X.224 13.9). CDT = octet2 & 0x0F.
type AK struct {
	CDT            uint8
	DestinationRef uint16
	YRTUNR         uint8
	Parameters     []Parameter
}

// EA is Expedited Acknowledge (X.224 13.10).
type EA struct {
	DestinationRef uint16
	YREDTUNR       uint8
	Parameters     []Parameter
}

// RJ is Reject (X.224 13.11). No variable part per spec.
type RJ struct {
	CDT            uint8
	DestinationRef uint16
	YRTUNR         uint8
}

// Known parameter codes for CR/CC variable part (v1).
const (
	ParamCallingSelector = 0xC1
	ParamCalledSelector  = 0xC2
	ParamTPDUSize        = 0xC0
)
