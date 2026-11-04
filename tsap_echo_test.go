// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
)

// TestAccept_EchoSelectors covers the CC selectors a server sends for each
// CR selector shape when EchoSelectors is set or not (X.224 §13.3.4).
func TestAccept_EchoSelectors(t *testing.T) {
	tsap := []byte{0x00, 0x01}
	cases := []struct {
		name                string
		local               []byte
		echo                bool
		crCalling, crCalled []byte
		wantCalling         []byte
		wantResponding      []byte
	}{
		{name: "no echo, no local", crCalling: tsap, crCalled: tsap},
		{name: "no echo, local", local: tsap, crCalling: tsap, crCalled: tsap, wantResponding: tsap},
		{name: "echo both", echo: true, crCalling: []byte{0x00, 0x00}, crCalled: tsap,
			wantCalling: []byte{0x00, 0x00}, wantResponding: tsap},
		{name: "echo absent stays absent", echo: true},
		{name: "echo calling only", echo: true, crCalling: tsap, wantCalling: tsap},
		{name: "echo four octets", echo: true, crCalling: []byte{0, 0, 0, 1}, crCalled: []byte{0, 0, 0, 1},
			wantCalling: []byte{0, 0, 0, 1}, wantResponding: []byte{0, 0, 0, 1}},
		{name: "echo one octet", echo: true, crCalling: []byte{1}, crCalled: []byte{1},
			wantCalling: []byte{1}, wantResponding: []byte{1}},
		{name: "echo empty", echo: true, crCalling: []byte{}, crCalled: []byte{},
			wantCalling: []byte{}, wantResponding: []byte{}},
		{name: "echo with local uses local", echo: true, local: tsap, crCalling: []byte{9}, crCalled: tsap,
			wantCalling: []byte{9}, wantResponding: tsap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			done := make(chan Decoded, 1)
			go func() {
				defer func() { _ = c1.Close() }()
				writePeerCR(t, c1, &CR{
					SourceRef:       0x77,
					CallingSelector: tc.crCalling,
					CalledSelector:  tc.crCalled,
					TPDUSize:        new(uint8(0x0A)),
				})
				done <- readPeerResponse(t, c1)
			}()
			conn, err := Accept(context.Background(), c2, ServerConfig{
				LocalSelector: tc.local,
				EchoSelectors: tc.echo,
			})
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			defer func() { _ = conn.Close() }()
			resp := <-done
			if resp.Type != TypeCC || resp.CC == nil {
				t.Fatalf("peer got %v, want CC", resp.Type)
			}
			assertSelector(t, "CC calling", resp.CC.CallingSelector, tc.wantCalling)
			assertSelector(t, "CC responding", resp.CC.CalledSelector, tc.wantResponding)
			neg := conn.Negotiated()
			assertSelector(t, "negotiated local", neg.LocalSelector, tc.wantResponding)
			assertSelector(t, "negotiated remote", neg.RemoteSelector, tc.crCalling)
		})
	}
}

// TestConnect_RespondingSelectorDiffers: 0xC2 in a CC names the responding
// TSAP, which may differ from the called one; the client keeps it.
func TestConnect_RespondingSelectorDiffers(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	go func() {
		cr := readPeerCR(t, c2)
		writeTPDU(t, c2, mustMarshal(t, &CC{
			DestinationRef:  cr.SourceRef,
			SourceRef:       2,
			CallingSelector: cr.CallingSelector,
			CalledSelector:  []byte{0x00, 0x00, 0x00, 0x01},
			TPDUSize:        new(uint8(0x0A)),
		}))
	}()

	conn, err := Connect(context.Background(), c1, ClientConfig{
		LocalSelector:  []byte{0x00, 0x01},
		RemoteSelector: []byte{0x00, 0x01},
		MaxTPDULength:  1024,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	assertSelector(t, "remote", conn.Negotiated().RemoteSelector, []byte{0, 0, 0, 1})
}

// TestConnect_StrictServerAddressUnknown: a server that requires a called
// TSAP refuses a CR without one with DR reason 3 (the REB500 behaviour of
// go-iec61850#28); the client reports it as a RejectionError.
func TestConnect_StrictServerAddressUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		called []byte
		ok     bool
	}{
		{name: "absent"},
		{name: "mismatch", called: []byte{0x00, 0x02}},
		{name: "four octets vs two", called: []byte{0, 0, 0, 1}},
		{name: "match", called: []byte{0x00, 0x01}, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			acc := make(chan error, 1)
			go func() {
				conn, err := Accept(context.Background(), c2, ServerConfig{LocalSelector: []byte{0x00, 0x01}})
				if err == nil {
					_ = conn.Close()
				}
				acc <- err
			}()
			conn, err := Connect(context.Background(), c1, ClientConfig{RemoteSelector: tc.called})
			if tc.ok {
				if err != nil {
					t.Fatalf("Connect: %v", err)
				}
				_ = conn.Close()
				if err := <-acc; err != nil {
					t.Fatalf("Accept: %v", err)
				}
				return
			}
			var rej *RejectionError
			if !errors.As(err, &rej) || rej.Reason != ReasonAddressUnknown {
				t.Fatalf("err = %v, want RejectionError AddressUnknown", err)
			}
			if err := <-acc; !errors.As(err, &rej) {
				t.Fatalf("Accept err = %v, want RejectionError", err)
			}
		})
	}
}

func assertSelector(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Fatalf("%s selector = %#v, want %#v", what, got, want)
	}
}
