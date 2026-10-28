// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func gapU8(v uint8) *uint8    { return &v }
func gapU16(v uint16) *uint16 { return &v }
func gapU32(v uint32) *uint32 { return &v }
func gapInt(v int) *int       { return &v }

// gapRawConn returns an open Conn over one end of a net.Pipe with no TPKT
// reader/writer, for exercising classification helpers that never do I/O.
func gapRawConn(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	c := newOpenConn(c1, nil, nil, NegotiatedParameters{MaxTPDULength: 128}, 0, SizeProfileRFC1006Compat, 0, nil)
	return c, c2
}

func TestGapConnAddrs(t *testing.T) {
	t.Parallel()
	var nilConn *Conn
	if nilConn.LocalAddr() != nil || nilConn.RemoteAddr() != nil {
		t.Fatal("nil Conn addrs must be nil")
	}
	noRaw := &Conn{}
	if noRaw.LocalAddr() != nil || noRaw.RemoteAddr() != nil {
		t.Fatal("Conn without raw stream addrs must be nil")
	}
	cli, srv := openPipePair(t, 0, 0)
	defer func() { _ = cli.Close(); _ = srv.Close() }()
	if a := cli.LocalAddr(); a == nil || a.Network() != "pipe" {
		t.Fatalf("LocalAddr = %v", a)
	}
	if a := srv.RemoteAddr(); a == nil || a.Network() != "pipe" {
		t.Fatalf("RemoteAddr = %v", a)
	}
}

func TestGapConnNilAndTerminalHelpers(t *testing.T) {
	t.Parallel()
	var nilConn *Conn
	if err := nilConn.Close(); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Close = %v", err)
	}
	if n := nilConn.Negotiated(); n.MaxTPDULength != 0 || n.LocalSelector != nil {
		t.Fatalf("nil Negotiated = %+v", n)
	}

	c, _ := gapRawConn(t)
	if err := c.terminalError(); err != nil {
		t.Fatalf("fresh terminalError = %v", err)
	}
	if n, ok := c.readProgress(); ok || n != 0 {
		t.Fatalf("unmetered readProgress = %d,%v", n, ok)
	}
	if n, ok := c.writeProgress(); ok || n != 0 {
		t.Fatalf("unmetered writeProgress = %d,%v", n, ok)
	}
	if err := c.abort(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("abort(nil) = %v", err)
	}
	// First cause wins.
	if err := c.abort(io.EOF); !errors.Is(err, ErrClosed) || errors.Is(err, io.EOF) {
		t.Fatalf("second abort = %v", err)
	}
	if err := c.requireOpen(); !errors.Is(err, ErrClosed) {
		t.Fatalf("requireOpen after abort = %v", err)
	}

	c2, _ := gapRawConn(t)
	if err := c2.abortOpen(false, nil); !errors.Is(err, ErrHandshake) || errors.Is(err, ErrIncompleteTSDU) {
		t.Fatalf("abortOpen(false,nil) = %v", err)
	}
	c3, _ := gapRawConn(t)
	if err := c3.abortOpen(true, ErrIncompleteTSDU); !errors.Is(err, ErrIncompleteTSDU) {
		t.Fatalf("abortOpen(true,incomplete) = %v", err)
	}

	// Non-open state without a terminal cause.
	c4, _ := gapRawConn(t)
	c4.state.Store(uint32(stateClosing))
	if err := c4.requireOpen(); !errors.Is(err, ErrClosed) {
		t.Fatalf("requireOpen in closing state = %v", err)
	}
}

func TestGapConnErrorStrings(t *testing.T) {
	t.Parallel()
	var nilRej *RejectionError
	var nilUnexp *UnexpectedTPDUError
	var nilDisc *DisconnectError
	tests := []struct {
		name string
		err  error
		want string
		is   error
	}{
		{"rejection nil", nilRej, "cotp: connection refused", ErrConnectionRefused},
		{"rejection", &RejectionError{Reason: ReasonNegotiationFailed}, "cotp: connection refused (reason 130)", ErrConnectionRefused},
		{"unexpected nil", nilUnexp, "cotp: unexpected TPDU", ErrUnexpectedTPDU},
		{"unexpected handshake", &UnexpectedTPDUError{Type: TypeDT, Phase: PhaseHandshake}, "cotp: unexpected DT during handshake", ErrUnexpectedTPDU},
		{"unexpected data", &UnexpectedTPDUError{Type: TypeCR, Phase: PhaseDataTransfer}, "cotp: unexpected CR during data transfer", ErrUnexpectedTPDU},
		{"disconnect nil", nilDisc, ErrDisconnected.Error(), ErrDisconnected},
		{"disconnect no cause", &DisconnectError{}, ErrDisconnected.Error(), ErrDisconnected},
		{"disconnect eof", &DisconnectError{Cause: io.EOF}, "cotp: peer disconnected: EOF", io.EOF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
			if !errors.Is(tc.err, tc.is) {
				t.Fatalf("errors.Is(%v, %v) = false", tc.err, tc.is)
			}
		})
	}
	if u := nilDisc.Unwrap(); len(u) != 1 || u[0] != ErrDisconnected {
		t.Fatalf("nil DisconnectError Unwrap = %v", u)
	}
}

func TestGapEncodePreferredMaxUnits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		units uint32
		want  []byte
	}{
		{1, []byte{0x01}},
		{0xff, []byte{0xff}},
		{0x100, []byte{0x01, 0x00}},
		{0xffff, []byte{0xff, 0xff}},
		{0x10000, []byte{0x01, 0x00, 0x00}},
		{0xffffff, []byte{0xff, 0xff, 0xff}},
		{0x1000000, []byte{0x01, 0x00, 0x00, 0x00}},
		{0xffffffff, []byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range tests {
		got, err := encodePreferredMaxUnits(tc.units)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("encode(%#x) = %x,%v want %x", tc.units, got, err, tc.want)
		}
		back, err := decodePreferredMaxUnits(got)
		if err != nil || back != tc.units {
			t.Fatalf("round-trip %#x = %#x,%v", tc.units, back, err)
		}
	}
	if _, err := encodePreferredMaxUnits(0); !errors.Is(err, ErrUnexpectedParameterLength) {
		t.Fatalf("encode(0) = %v", err)
	}
}

func TestGapValidateReassemblyBound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n, max  int
		wantErr bool
	}{
		{10, 10, false},
		{11, 10, true},
		{DefaultMaxTSDULength, 0, false},
		{DefaultMaxTSDULength + 1, 0, true},
	}
	for _, tc := range tests {
		err := validateReassemblyBound(tc.n, tc.max)
		if tc.wantErr != (err != nil) || (err != nil && !errors.Is(err, ErrTSDUTooLarge)) {
			t.Fatalf("validateReassemblyBound(%d,%d) = %v", tc.n, tc.max, err)
		}
	}
}

func TestGapRejectionFromDR(t *testing.T) {
	t.Parallel()
	err := rejectionFromDR(nil)
	var rej *RejectionError
	if !errors.Is(err, ErrConnectionRefused) || errors.As(err, &rej) {
		t.Fatalf("rejectionFromDR(nil) = %v", err)
	}
	info := []byte{1, 2}
	err = rejectionFromDR(&DR{Reason: uint8(ReasonAddressUnknown), UserData: info})
	if !errors.As(err, &rej) || rej.Reason != ReasonAddressUnknown || !bytes.Equal(rej.Info, info) {
		t.Fatalf("rejectionFromDR = %v", err)
	}
	info[0] = 9
	if rej.Info[0] != 1 {
		t.Fatal("Info must be a defensive copy")
	}
}

func TestGapFallbackStandard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in       int
		wantSize int
		wantCode uint8
		wantErr  bool
	}{
		{127, 0, 0, true},
		{128, 128, 0x07, false},
		{200, 128, 0x07, false},
		{1000, 512, 0x09, false},
		{DefaultMaxTPDULength, 32768, 0x0F, false},
		{65536, 65536, 0x10, false},
	}
	for _, tc := range tests {
		size, code, err := fallbackStandard(tc.in)
		if tc.wantErr {
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("fallbackStandard(%d) err = %v", tc.in, err)
			}
			continue
		}
		if err != nil || size != tc.wantSize || code != tc.wantCode {
			t.Fatalf("fallbackStandard(%d) = %d,%#x,%v", tc.in, size, code, err)
		}
	}
	if _, _, err := normalizeStandardCeiling(1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalizeStandardCeiling(1) = %v", err)
	}
}

func TestGapMaxSegmentPayload(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]int{0: 0, 3: 0, 4: 1, 128: 125, 65531: 65528} {
		if got := maxSegmentPayload(in); got != want {
			t.Fatalf("maxSegmentPayload(%d) = %d want %d", in, got, want)
		}
	}
}

func TestGapPreferredUnitsAndEffective(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in        int
		units     uint32
		effective int
		wantErr   bool
	}{
		{0, 511, 511 * 128, false},
		{128, 1, 128, false},
		{1000, 7, 896, false},
		{DefaultMaxTPDULength, 511, 65408, false},
		{100, 0, 0, true},
		{70000, 0, 0, true},
	}
	for _, tc := range tests {
		u, eff, err := preferredUnitsAndEffective(tc.in)
		if tc.wantErr {
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("preferredUnitsAndEffective(%d) err = %v", tc.in, err)
			}
			continue
		}
		if err != nil || u != tc.units || eff != tc.effective {
			t.Fatalf("preferredUnitsAndEffective(%d) = %d,%d,%v", tc.in, u, eff, err)
		}
	}
}

func TestGapSelectStandardPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		peer, srv, cb int
		wantEff       int
		wantCode      uint8
		wantErr       error
	}{
		{"server invalid", 1024, 1, 0, 0, 0, ErrInvalidConfig},
		{"callback invalid", 1024, 2048, 1, 0, 0, ErrInvalidConfig},
		{"server smaller", 2048, 1024, 0, 1024, 0x0A, nil},
		{"callback smaller", 2048, 4096, 512, 512, 0x09, nil},
		{"callback larger", 256, 4096, 2048, 256, 0x08, nil},
		{"non-standard peer refloored", 300, 4096, 0, 256, 0x08, nil},
		{"peer below minimum", 100, 4096, 0, 0, 0, ErrInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sel, err := selectStandardPath(tc.peer, tc.srv, tc.cb)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || sel.Path != sizePathStandard || sel.Effective != tc.wantEff || sel.StandardCode == nil || *sel.StandardCode != tc.wantCode {
				t.Fatalf("sel = %+v err = %v", sel, err)
			}
		})
	}
}

func TestGapSelectSizeBranches(t *testing.T) {
	t.Parallel()
	if _, err := selectSize(sizeOffer{Omitted: true}, 0, 0, SizeProfile(9)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad profile = %v", err)
	}
	if _, err := selectSize(sizeOffer{Omitted: true}, 1, 0, SizeProfileRFC1006Compat); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad server = %v", err)
	}
	if _, err := selectSize(sizeOffer{Omitted: true}, 0, 1, SizeProfileRFC1006Compat); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad callback = %v", err)
	}

	// Omitted CR, callback lowers the ceiling to a standard size.
	sel, err := selectOmittedCR(DefaultMaxTPDULength, 1024, SizeProfileRFC1006Compat)
	if err != nil || sel.Path != sizePathStandard || sel.Effective != 1024 || *sel.StandardCode != 0x0A {
		t.Fatalf("omitted cb 1024 = %+v,%v", sel, err)
	}
	// Omitted CR, non-standard ceiling is floored.
	sel, err = selectOmittedCR(1000, 0, SizeProfilePreferredMaximum)
	if err != nil || sel.Effective != 512 || *sel.StandardCode != 0x09 {
		t.Fatalf("omitted 1000 = %+v,%v", sel, err)
	}
	// Omitted CR, callback larger than server keeps server ceiling.
	sel, err = selectOmittedCR(DefaultMaxTPDULength, 65536, SizeProfileRFC1006Compat)
	if err != nil || sel.Path != sizePathOmitted || sel.Effective != DefaultMaxTPDULength {
		t.Fatalf("omitted default = %+v,%v", sel, err)
	}

	// Preferred path with a callback ceiling.
	sel, err = selectPreferredPath(8192, DefaultMaxTPDULength, 1000)
	if err != nil || sel.Path != sizePathPreferred || sel.Effective != 896 || *sel.PreferredUnits != 7 {
		t.Fatalf("preferred cb = %+v,%v", sel, err)
	}
	if _, err := selectPreferredPath(8192, 1, 0); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("preferred bad server = %v", err)
	}
	if _, err := selectPreferredPath(8192, 4096, 1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("preferred bad callback = %v", err)
	}
	if _, err := selectPreferredPath(100, 4096, 0); !errors.Is(err, ErrHandshake) {
		t.Fatalf("preferred below minimum = %v", err)
	}

	// Dispatch through selectSize: preferred wins over standard.
	sel, err = selectSize(sizeOffer{Standard: gapInt(1024), Preferred: gapInt(2048)}, 4096, 0, SizeProfilePreferredMaximum)
	if err != nil || sel.Path != sizePathPreferred || sel.Effective != 2048 {
		t.Fatalf("selectSize preferred = %+v,%v", sel, err)
	}
	sel, err = selectSize(sizeOffer{Standard: gapInt(1024)}, 4096, 0, SizeProfileRFC1006Compat)
	if err != nil || sel.Path != sizePathStandard || sel.Effective != 1024 {
		t.Fatalf("selectSize standard = %+v,%v", sel, err)
	}
}

func TestGapInterpretCCSize(t *testing.T) {
	t.Parallel()
	compat, pref := SizeProfileRFC1006Compat, SizeProfilePreferredMaximum
	tests := []struct {
		name    string
		sent    sizeOffer
		std     *uint8
		units   *uint32
		profile SizeProfile
		want    int
		wantErr error
	}{
		{"bad profile", sizeOffer{Omitted: true}, nil, nil, SizeProfile(7), 0, ErrInvalidConfig},
		{"both params", sizeOffer{Standard: gapInt(1024)}, gapU8(0x0A), gapU32(8), compat, 0, ErrHandshake},
		{"omitted under preferred", sizeOffer{Preferred: gapInt(1024)}, nil, nil, pref, 0, ErrHandshake},
		{"compat omission uses proposal", sizeOffer{Standard: gapInt(1024)}, nil, nil, compat, 1024, nil},
		{"compat omission capped", sizeOffer{Standard: gapInt(65536)}, nil, nil, compat, DefaultMaxTPDULength, nil},
		{"compat omission omitted CR", sizeOffer{Omitted: true}, nil, nil, compat, DefaultMaxTPDULength, nil},
		{"preferred not offered", sizeOffer{Standard: gapInt(1024)}, nil, gapU32(4), compat, 0, ErrHandshake},
		{"preferred zero units", sizeOffer{Preferred: gapInt(1024)}, nil, gapU32(0), pref, 0, ErrHandshake},
		{"preferred too many units", sizeOffer{Preferred: gapInt(1024)}, nil, gapU32(512), pref, 0, ErrHandshake},
		{"preferred exceeds offer", sizeOffer{Preferred: gapInt(1024)}, nil, gapU32(9), pref, 0, ErrHandshake},
		{"preferred ok", sizeOffer{Preferred: gapInt(1024)}, nil, gapU32(4), pref, 512, nil},
		{"standard not offered", sizeOffer{Preferred: gapInt(1024)}, gapU8(0x09), nil, pref, 0, ErrHandshake},
		{"standard bad code", sizeOffer{Standard: gapInt(1024)}, gapU8(0x11), nil, compat, 0, ErrHandshake},
		{"standard omitted CR capped", sizeOffer{Omitted: true}, gapU8(0x10), nil, compat, DefaultMaxTPDULength, nil},
		{"standard omitted CR smaller", sizeOffer{Omitted: true}, gapU8(0x0A), nil, compat, 1024, nil},
		{"standard exceeds offer", sizeOffer{Standard: gapInt(1024)}, gapU8(0x0B), nil, compat, 0, ErrHandshake},
		{"standard ok", sizeOffer{Standard: gapInt(1024)}, gapU8(0x09), nil, compat, 512, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := interpretCCSize(tc.sent, tc.std, tc.units, tc.profile)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %d,%v want %d", got, err, tc.want)
			}
		})
	}
}

func TestGapConfigPreflight(t *testing.T) {
	t.Parallel()
	long := make([]byte, MaxParameterValueLength+1)
	clientCases := []struct {
		name string
		cfg  ClientConfig
	}{
		{"profile", ClientConfig{SizeProfile: SizeProfile(5)}},
		{"max tpdu", ClientConfig{MaxTPDULength: 1}},
		{"max tsdu", ClientConfig{MaxTSDULength: -1}},
		{"local selector", ClientConfig{LocalSelector: long}},
		{"remote selector", ClientConfig{RemoteSelector: long}},
		{"connect data", ClientConfig{ConnectData: make([]byte, MaxConnectDataLength+1)}},
	}
	for _, tc := range clientCases {
		if _, _, err := tc.cfg.preflight(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("client %s: %v", tc.name, err)
		}
	}
	tpdu, tsdu, err := ClientConfig{}.preflight()
	if err != nil || tpdu != DefaultMaxTPDULength || tsdu != DefaultMaxTSDULength {
		t.Fatalf("client defaults = %d,%d,%v", tpdu, tsdu, err)
	}
	tpdu, tsdu, err = ClientConfig{MaxTPDULength: 1024, MaxTSDULength: 77}.preflight()
	if err != nil || tpdu != 1024 || tsdu != 77 {
		t.Fatalf("client explicit = %d,%d,%v", tpdu, tsdu, err)
	}

	serverCases := []struct {
		name string
		cfg  ServerConfig
	}{
		{"profile", ServerConfig{SizeProfile: SizeProfile(5)}},
		{"max tpdu", ServerConfig{MaxTPDULength: 70000}},
		{"max tsdu", ServerConfig{MaxTSDULength: -5}},
		{"local selector", ServerConfig{LocalSelector: long}},
	}
	for _, tc := range serverCases {
		if _, _, err := tc.cfg.preflight(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("server %s: %v", tc.name, err)
		}
	}
	tpdu, tsdu, err = ServerConfig{MaxTSDULength: 9}.preflight()
	if err != nil || tpdu != DefaultMaxTPDULength || tsdu != 9 {
		t.Fatalf("server = %d,%d,%v", tpdu, tsdu, err)
	}
}

func TestGapStringMethods(t *testing.T) {
	t.Parallel()
	longSel := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"param empty", Parameter{Code: 0xC1}.String(), "0xC1=[]"},
		{"param short", Parameter{Code: 0xC1, Value: []byte{0xAB}}.String(), "0xC1=ab"},
		{"param long", Parameter{Code: 0xC2, Value: longSel}.String(), "0xC2=0102030405060708...(10)"},
		{"CR full", (&CR{
			DestinationRef: 0, SourceRef: 7, CallingSelector: longSel, CalledSelector: []byte{0xAA},
			TPDUSize: gapU8(0x0A), PreferredMaxTPDUSize: gapU32(8),
			Parameters: []Parameter{{Code: 0x99}}, UserData: []byte{1, 2},
		}).String(), "CR{CDT:0 DST:0 SRC:7 Class:0 calling:0102030405060708 called:aa size:10 pref:8 params:1 userdata:2}"},
		{"CC full", (&CC{
			DestinationRef: 7, SourceRef: 9, CallingSelector: []byte{}, CalledSelector: longSel,
			TPDUSize: gapU8(0x0B), PreferredMaxTPDUSize: gapU32(2),
			Parameters: []Parameter{{Code: 0x99}, {Code: 0x98}}, UserData: []byte{1},
		}).String(), "CC{CDT:0 DST:7 SRC:9 Class:0 calling: called:0102030405060708 size:11 pref:2 params:2 userdata:1}"},
		{"DT full", (&DT{EOT: true, TPDUNR: gapU8(3), DestinationRef: gapU16(5), Parameters: []Parameter{{Code: 1}}, UserData: []byte{1, 2, 3}}).String(),
			"DT{EOT:true NR:3 DST:5 params:1 userdata:3}"},
		{"AK params", (&AK{CDT: 1, DestinationRef: 2, YRTUNR: 3, Parameters: []Parameter{{Code: 1}}}).String(), "AK{CDT:1 DST:2 YRTUNR:3 params:1}"},
		{"EA params", (&EA{DestinationRef: 2, YREDTUNR: 4, Parameters: []Parameter{{Code: 1}}}).String(), "EA{DST:2 YREDTUNR:4 params:1}"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, tc.got, tc.want)
		}
	}
	if got := truncHex([]byte{1, 2}); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatalf("truncHex short = %x", got)
	}
}

// gapTimeoutErr is a net.Error that reports a timeout.
type gapTimeoutErr struct{}

func (gapTimeoutErr) Error() string   { return "i/o timeout" }
func (gapTimeoutErr) Timeout() bool   { return true }
func (gapTimeoutErr) Temporary() bool { return true }

func TestGapClassifyIOPhase(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	// Parallel subtests outlive this function body, so the deadline context
	// must not be canceled by a defer here.
	withDeadline, cancelDL := context.WithTimeout(context.Background(), time.Hour)
	t.Cleanup(cancelDL)

	tests := []struct {
		name    string
		ctx     context.Context
		err     error
		mid     bool
		wantIs  []error
		wantNot []error
	}{
		{"canceled ctx", canceled, boom, false, []error{ErrClosed, context.Canceled}, []error{ErrDisconnected}},
		{"timeout under deadline", withDeadline, gapTimeoutErr{}, false, []error{ErrClosed, context.DeadlineExceeded}, nil},
		{"timeout without deadline", context.Background(), os.ErrDeadlineExceeded, false, []error{os.ErrDeadlineExceeded}, []error{ErrClosed, ErrDisconnected}},
		{"eof idle", context.Background(), io.EOF, false, []error{ErrDisconnected, io.EOF}, []error{ErrIncompleteTSDU}},
		{"eof mid", context.Background(), io.EOF, true, []error{ErrDisconnected, io.EOF, ErrIncompleteTSDU}, nil},
		{"unexpected eof idle", context.Background(), io.ErrUnexpectedEOF, false, []error{ErrDisconnected, ErrIncompleteTSDU}, nil},
		{"reset idle", context.Background(), syscall.ECONNRESET, false, []error{ErrDisconnected, syscall.ECONNRESET}, []error{ErrIncompleteTSDU}},
		{"reset mid", context.Background(), net.ErrClosed, true, []error{ErrDisconnected, ErrIncompleteTSDU}, nil},
		{"other mid", context.Background(), boom, true, []error{ErrIncompleteTSDU, ErrDisconnected, boom}, nil},
		{"other idle", context.Background(), boom, false, []error{boom}, []error{ErrDisconnected, ErrIncompleteTSDU}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := gapRawConn(t)
			got := c.classifyIOPhase(tc.ctx, tc.err, tc.mid)
			for _, w := range tc.wantIs {
				if !errors.Is(got, w) {
					t.Errorf("errors.Is(%v, %v) = false", got, w)
				}
			}
			for _, w := range tc.wantNot {
				if errors.Is(got, w) {
					t.Errorf("errors.Is(%v, %v) = true", got, w)
				}
			}
			if c.terminalKind() != terminalAborted {
				t.Errorf("terminalKind = %v want aborted", c.terminalKind())
			}
			// Once terminal, the stored cause is returned regardless of err.
			if again := c.classifyIOPhase(context.Background(), errors.New("later"), false); again != got {
				t.Errorf("terminal re-classify = %v want %v", again, got)
			}
		})
	}
	c, _ := gapRawConn(t)
	if err := c.classifyIOPhase(context.Background(), nil, true); err != nil {
		t.Fatalf("nil err = %v", err)
	}
	if c.terminalKind() != terminalNone {
		t.Fatal("nil err must not abort")
	}
}

func TestGapConnectIOError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	withDeadline, cancelDL := context.WithTimeout(context.Background(), time.Hour)
	defer cancelDL()

	if err := connectIOError(context.Background(), nil); err != nil {
		t.Fatalf("nil = %v", err)
	}
	if err := connectIOError(canceled, boom); !errors.Is(err, ErrClosed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}
	if err := connectIOError(withDeadline, gapTimeoutErr{}); !errors.Is(err, ErrClosed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline timeout = %v", err)
	}
	if err := connectIOError(context.Background(), io.EOF); !errors.Is(err, ErrDisconnected) || !errors.Is(err, io.EOF) {
		t.Fatalf("eof = %v", err)
	}
	if err := connectIOError(context.Background(), boom); err != boom {
		t.Fatalf("passthrough = %v", err)
	}
}

func TestGapDecodeFixedTPDUErrors(t *testing.T) {
	t.Parallel()
	type dec func([]byte) error
	ak := func(b []byte) error { _, err := DecodeAK(b); return err }
	ea := func(b []byte) error { _, err := DecodeEA(b); return err }
	rj := func(b []byte) error { _, err := DecodeRJ(b); return err }
	dt := func(b []byte) error { _, err := DecodeDT(b); return err }
	tests := []struct {
		name string
		fn   dec
		in   []byte
		want error
	}{
		{"AK short", ak, []byte{4, 0x60, 0, 1}, ErrTooShort},
		{"AK bad LI", ak, []byte{255, 0x60, 0, 1, 0}, ErrInvalidLI},
		{"AK LI below fixed", ak, []byte{3, 0x60, 0, 1, 0}, ErrInvalidLI},
		{"AK header past buffer", ak, []byte{6, 0x60, 0, 1, 0}, ErrTooShort},
		{"AK wrong code", ak, []byte{4, 0x50, 0, 1, 0}, ErrInvalidTPDUCode},
		{"AK bad params", ak, []byte{6, 0x61, 0, 1, 0, 0x85, 0x05}, ErrMalformedParameter},
		{"EA short", ea, []byte{4, 0x20}, ErrTooShort},
		{"EA bad LI", ea, []byte{255, 0x20, 0, 1, 0}, ErrInvalidLI},
		{"EA LI below fixed", ea, []byte{2, 0x20, 0, 1, 0}, ErrInvalidLI},
		{"EA header past buffer", ea, []byte{8, 0x20, 0, 1, 0}, ErrTooShort},
		{"EA wrong code", ea, []byte{4, 0x21, 0, 1, 0}, ErrInvalidTPDUCode},
		{"EA bad params", ea, []byte{6, 0x20, 0, 1, 0, 0x85, 0x05}, ErrMalformedParameter},
		{"RJ short", rj, []byte{4, 0x50, 0}, ErrTooShort},
		{"RJ bad LI", rj, []byte{255, 0x50, 0, 1, 0}, ErrInvalidLI},
		{"RJ variable part", rj, []byte{5, 0x50, 0, 1, 0, 0}, ErrMalformedParameter},
		{"RJ LI below fixed", rj, []byte{3, 0x50, 0, 1, 0}, ErrInvalidLI},
		{"RJ wrong code", rj, []byte{4, 0x60, 0, 1, 0}, ErrInvalidTPDUCode},
		{"DT short", dt, []byte{2}, ErrTooShort},
		{"DT bad LI", dt, []byte{255, 0xF0, 0x80}, ErrInvalidLI},
		{"DT header past buffer", dt, []byte{2, 0xF0}, ErrTooShort},
		{"DT wrong code", dt, []byte{2, 0xE0, 0x80}, ErrInvalidTPDUCode},
		{"DT LI 3 unsupported", dt, []byte{3, 0xF0, 0x80, 0}, ErrUnsupportedDTVariant},
		{"DT LI 1 unsupported", dt, []byte{1, 0xF0}, ErrUnsupportedDTVariant},
		{"DT normal bad params", dt, []byte{6, 0xF0, 0, 1, 0x80, 0x85, 0x05}, ErrMalformedParameter},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.fn(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v want %v", err, tc.want)
			}
		})
	}

	got, err := DecodeRJ([]byte{4, 0x53, 0x12, 0x34, 9})
	if err != nil || got.CDT != 3 || got.DestinationRef != 0x1234 || got.YRTUNR != 9 {
		t.Fatalf("DecodeRJ ok = %+v,%v", got, err)
	}
	akv, err := DecodeAK([]byte{6, 0x62, 0, 5, 1, 0x85, 0x00})
	if err != nil || akv.CDT != 2 || akv.DestinationRef != 5 || len(akv.Parameters) != 1 || akv.Parameters[0].Code != 0x85 {
		t.Fatalf("DecodeAK with params = %+v,%v", akv, err)
	}
	eav, err := DecodeEA([]byte{6, 0x20, 0, 5, 2, 0x85, 0x00})
	if err != nil || eav.YREDTUNR != 2 || len(eav.Parameters) != 1 {
		t.Fatalf("DecodeEA with params = %+v,%v", eav, err)
	}
	dtv, err := DecodeDT([]byte{6, 0xF0, 0, 7, 0x81, 0x85, 0x00, 0xAA})
	if err != nil || dtv.DestinationRef == nil || *dtv.DestinationRef != 7 || *dtv.TPDUNR != 1 || !dtv.EOT ||
		len(dtv.Parameters) != 1 || !bytes.Equal(dtv.UserData, []byte{0xAA}) {
		t.Fatalf("DecodeDT normal = %+v,%v", dtv, err)
	}
}

func TestGapDecodeOpenDT(t *testing.T) {
	t.Parallel()
	dr := mustMarshal(t, &DR{DestinationRef: 1, SourceRef: 2})
	cr := mustMarshal(t, &CR{SourceRef: 1})
	tests := []struct {
		name   string
		in     []byte
		max    int
		wantIs []error
	}{
		{"too long", []byte{2, 0xF0, 0x80, 1, 2}, 4, []error{ErrHandshake}},
		{"too short", []byte{2}, 128, []error{ErrHandshake, ErrTooShort}},
		{"undecodable", []byte{2, 0x00, 0x80}, 128, []error{ErrHandshake}},
		{"DR in open state", dr, 128, []error{ErrUnexpectedTPDU, ErrDisconnected}},
		{"CR in open state", cr, 128, []error{ErrUnexpectedTPDU}},
		{"normal DT", []byte{4, 0xF0, 0, 1, 0x80, 0xAA}, 128, []error{ErrHandshake}},
		{"nonzero TPDU-NR", []byte{2, 0xF0, 0x81, 0xAA}, 128, []error{ErrHandshake}},
		{"ROA bit", []byte{2, 0xF1, 0x80, 0xAA}, 128, []error{ErrHandshake}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := decodeOpenDT(tc.in, tc.max)
			if err == nil {
				t.Fatal("expected error")
			}
			for _, w := range tc.wantIs {
				if !errors.Is(err, w) {
					t.Fatalf("errors.Is(%v, %v) = false", err, w)
				}
			}
		})
	}
	var u *UnexpectedTPDUError
	if _, err := decodeOpenDT(cr, 128); !errors.As(err, &u) || u.Type != TypeCR || u.Phase != PhaseDataTransfer {
		t.Fatalf("CR open-state error = %v", err)
	}
	dt, err := decodeOpenDT([]byte{2, 0xF0, 0x80, 0xAA, 0xBB}, 128)
	if err != nil || !dt.EOT || !bytes.Equal(dt.UserData, []byte{0xAA, 0xBB}) {
		t.Fatalf("valid DT = %+v,%v", dt, err)
	}
	if err := validateOpenDTParameters([]Parameter{{Code: 0xC5}}); !errors.Is(err, ErrHandshake) || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("forbidden DT param = %v", err)
	}
	if err := validateOpenDTParameters([]Parameter{{Code: 0x99}}); !errors.Is(err, ErrHandshake) || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown DT param = %v", err)
	}
}

func TestGapExtractUserData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr error
	}{
		{"peek error", []byte{2}, nil, ErrTooShort},
		{"DT ok", []byte{2, 0xF0, 0x80, 1, 2}, []byte{1, 2}, nil},
		{"DT decode error", []byte{3, 0xF0, 0x80, 0}, nil, ErrUnsupportedDTVariant},
		{"ED ok", []byte{4, 0x10, 0, 1, 0x80, 0xEE}, []byte{0xEE}, nil},
		{"ED decode error", []byte{4, 0x10, 0, 1, 0x80}, nil, ErrInvalidEDUserDataLength},
		{"not DT or ED", mustMarshal(t, &DR{SourceRef: 1}), nil, ErrInvalidTPDUCode},
	}
	for _, tc := range tests {
		got, err := ExtractUserData(tc.in)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v want %v", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Fatalf("%s: got %x,%v", tc.name, got, err)
		}
	}
}

func TestGapReferenceAllocator(t *testing.T) {
	t.Parallel()
	// Zero-value allocator lazily creates its map; next starts at 0 so 0 is skipped.
	var zero referenceAllocator
	ref, err := zero.Allocate()
	if err != nil || ref != 1 {
		t.Fatalf("zero-value Allocate = %d,%v", ref, err)
	}

	a := newReferenceAllocator()
	a.Release(0) // no-op
	if a.Len() != 0 {
		t.Fatal("Release(0) changed state")
	}

	// Wrap: 65535, then skip 0, then skip still-active 1.
	if r, _ := a.Allocate(); r != 1 {
		t.Fatalf("first = %d", r)
	}
	a.next = 65535
	if r, _ := a.Allocate(); r != 65535 {
		t.Fatalf("pre-wrap = %d", r)
	}
	if r, _ := a.Allocate(); r != 2 {
		t.Fatalf("post-wrap = %d (want skip 0 and active 1)", r)
	}
	a.Release(2)
	if a.Active(2) || !a.Active(1) || !a.Active(65535) {
		t.Fatal("Active state wrong after Release")
	}

	// Exhaustion.
	full := newReferenceAllocator()
	for i := 1; i <= 65535; i++ {
		full.active[uint16(i)] = struct{}{}
	}
	if _, err := full.Allocate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("exhausted Allocate = %v", err)
	}
}

func TestGapHandshakeValidators(t *testing.T) {
	t.Parallel()
	if err := validateClass0CRFixed(1, 0); !errors.Is(err, ErrHandshake) {
		t.Fatalf("CR CDT = %v", err)
	}
	if err := validateClass0CRFixed(0, 0x01); !errors.Is(err, ErrHandshake) {
		t.Fatalf("CR class option = %v", err)
	}
	if err := validateClass0CRFixed(0, 0); err != nil {
		t.Fatalf("CR fixed ok = %v", err)
	}
	if err := validateCRReferences(1, 1); !errors.Is(err, ErrHandshake) {
		t.Fatalf("CR dst = %v", err)
	}
	if err := validateCRReferences(0, 0); !errors.Is(err, ErrHandshake) {
		t.Fatalf("CR src = %v", err)
	}
	if err := validateCRReferences(0, 5); err != nil {
		t.Fatalf("CR refs ok = %v", err)
	}
	d, err := defaultAutoAccept(ServerConfig{}, ConnectIndication{ProposedClass: Class(2)})
	if err != nil || d.Action != ConnectReject || d.RejectReason != ReasonNegotiationFailed {
		t.Fatalf("defaultAutoAccept class 2 = %+v,%v", d, err)
	}
}
