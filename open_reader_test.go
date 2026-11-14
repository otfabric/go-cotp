// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-tpkt"
)

// A packet longer than the negotiated TPDU size is refused from its header,
// before the payload is read, on both sides of the connection.
func TestOpenReader_RefusesLongPacketFromHeader(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
			reader, peer := srv, cli
			if side == "client" {
				reader, peer = cli, srv
			}
			// Only the header of a 1000-octet packet: no payload follows.
			go func() { _, _ = peer.raw.Write([]byte{3, 0, 0x03, 0xE8}) }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := reader.ReadTSDU(ctx)
			if !errors.Is(err, ErrHandshake) || !errors.Is(err, tpkt.ErrPacketTooLarge) {
				t.Fatalf("err = %v, want ErrHandshake and tpkt.ErrPacketTooLarge", err)
			}
		})
	}
}

// The largest packet the negotiated size allows still reads.
func TestOpenReader_AcceptsNegotiatedMaximum(t *testing.T) {
	cli, srv := openPipePair(t, 128, DefaultMaxTSDULength)
	user := make([]byte, 125) // 3 + 125 = 128
	go func() { _ = cli.writer.WritePacket(mustMarshal(t, &DT{EOT: true, UserData: user})) }()
	got, err := srv.ReadTSDU(context.Background())
	if err != nil || len(got) != len(user) {
		t.Fatalf("got %d octets, err %v; want %d octets", len(got), err, len(user))
	}
}

func TestOpenReader_KeepsHandshakeReaderOnInvalidLimit(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	hs, err := tpkt.NewReader(c1, tpkt.ReaderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := openReader(c1, tpkt.MaxPacketLength, hs); got != hs {
		t.Fatal("openReader replaced the reader with an invalid limit")
	}
	if got := openReader(c1, 128, hs); got == hs || got == nil {
		t.Fatal("openReader kept the handshake reader for a valid limit")
	}
}
