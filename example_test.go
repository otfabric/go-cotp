package cotp_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/otfabric/go-cotp"
	"github.com/otfabric/go-tpkt"
)

// Minimal COTP TPDUs for examples (same as in package tests).
var (
	exampleCR = []byte{0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	exampleDT = []byte{0x02, 0xF0, 0x00, 0xDE, 0xAD}
)

// ExampleDecode demonstrates reading a TPKT frame and decoding the COTP TPDU.
// The payload is obtained with tpkt.Reader.ReadFrame; then cotp.Decode parses it.
func ExampleDecode() {
	// Build a TPKT frame containing a COTP CR (e.g. as if received from the wire).
	pkt, err := tpkt.Encode(exampleCR)
	if err != nil {
		fmt.Println("encode:", err)
		return
	}

	// Simulate reading from a connection: wrap the packet in a reader.
	r := tpkt.NewReader(bytes.NewReader(pkt))
	payload, err := r.ReadFrame()
	if err != nil && err != io.EOF {
		fmt.Println("ReadFrame:", err)
		return
	}

	msg, err := cotp.Decode(payload)
	if err != nil {
		fmt.Println("Decode:", err)
		return
	}

	switch msg.Type {
	case cotp.TypeCR:
		fmt.Println("CR", msg.CR)
	case cotp.TypeCC:
		fmt.Println("CC", msg.CC)
	case cotp.TypeDT:
		fmt.Println("DT userdata len:", len(msg.DT.UserData))
	default:
		fmt.Println("TPDU:", msg.Type)
	}
	// Output: CR CR{CDT:0 DST:0 SRC:0 Class:0}
}

// ExampleExtractUserData shows how to get DT user data without full decode.
func ExampleExtractUserData() {
	pkt, _ := tpkt.Encode(exampleDT)
	r := tpkt.NewReader(bytes.NewReader(pkt))
	payload, _ := r.ReadFrame()

	userData, err := cotp.ExtractUserData(payload)
	if err != nil {
		fmt.Println("ExtractUserData:", err)
		return
	}
	fmt.Printf("userdata: %v\n", userData)
	// Output: userdata: [222 173]
}

// ExampleDecodeWithRaw shows decoding with raw bytes retained for replay or debug.
func ExampleDecodeWithRaw() {
	raw := exampleCR
	d, err := cotp.DecodeWithRaw(raw)
	if err != nil {
		fmt.Println("DecodeWithRaw:", err)
		return
	}
	fmt.Println("Type:", d.Type)
	fmt.Println("Raw len:", len(d.Raw))
	// Re-decode from Raw to verify
	d2, _ := cotp.Decode(d.Raw)
	fmt.Println("Replay same type:", d2.Type == d.Type)
	// Output:
	// Type: CR
	// Raw len: 7
	// Replay same type: true
}

// ExampleEncode demonstrates building a CR, marshaling it, and writing it as a TPKT frame.
func ExampleEncode() {
	cr := &cotp.CR{
		CDT:            0,
		DestinationRef: 0,
		SourceRef:      0,
		ClassOption:    0,
	}
	encoded, err := cr.MarshalBinary()
	if err != nil {
		fmt.Println("MarshalBinary:", err)
		return
	}

	var buf bytes.Buffer
	w := tpkt.NewWriter(&buf)
	n, err := w.WriteFrame(encoded)
	if err != nil {
		fmt.Println("WriteFrame:", err)
		return
	}
	fmt.Println("wrote", n, "bytes, frame len", buf.Len())
	// Output: wrote 11 bytes, frame len 11
}

// TestTpktCotpIntegration verifies that tpkt and cotp work together: write TPKT frames, read them, decode COTP.
func TestTpktCotpIntegration(t *testing.T) {
	// Build buffer with two TPKT frames: CR and DT.
	pktCR, err := tpkt.Encode(exampleCR)
	if err != nil {
		t.Fatalf("tpkt.Encode(CR): %v", err)
	}
	pktDT, err := tpkt.Encode(exampleDT)
	if err != nil {
		t.Fatalf("tpkt.Encode(DT): %v", err)
	}
	var buf bytes.Buffer
	buf.Write(pktCR)
	buf.Write(pktDT)

	r := tpkt.NewReader(&buf)

	// First frame: CR
	payload, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 1: %v", err)
	}
	msg, err := cotp.Decode(payload)
	if err != nil {
		t.Fatalf("Decode CR: %v", err)
	}
	if msg.Type != cotp.TypeCR || msg.CR == nil {
		t.Errorf("expected CR, got Type=%v CR=%v", msg.Type, msg.CR != nil)
	}

	// Second frame: DT
	payload, err = r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame 2: %v", err)
	}
	msg, err = cotp.Decode(payload)
	if err != nil {
		t.Fatalf("Decode DT: %v", err)
	}
	if msg.Type != cotp.TypeDT || msg.DT == nil {
		t.Errorf("expected DT, got Type=%v DT=%v", msg.Type, msg.DT != nil)
	}
	if len(msg.DT.UserData) != 2 || msg.DT.UserData[0] != 0xDE || msg.DT.UserData[1] != 0xAD {
		t.Errorf("DT UserData = %v", msg.DT.UserData)
	}
}
