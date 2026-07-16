// SPDX-License-Identifier: MIT

package cotp_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-cotp"
)

func openTP0Pair(t *testing.T, clientCfg cotp.ClientConfig, serverCfg cotp.ServerConfig) (client, server *cotp.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	var srv *cotp.Conn
	go func() {
		var err error
		srv, err = cotp.Accept(context.Background(), c2, serverCfg)
		errCh <- err
	}()
	cli, err := cotp.Connect(context.Background(), c1, clientCfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestIntegration_ClientToServerTSDU(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	want := []byte("hello-tp0")
	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	if err := cli.WriteTSDU(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIntegration_ServerToClientTSDU(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	want := []byte("reply-tp0")
	errCh := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = cli.ReadTSDU(context.Background())
		errCh <- err
	}()
	if err := srv.WriteTSDU(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIntegration_FullDuplex(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	a := []byte("c2s")
	b := []byte("s2c")
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	wg.Add(4)
	go func() { defer wg.Done(); errs <- cli.WriteTSDU(context.Background(), a) }()
	go func() { defer wg.Done(); errs <- srv.WriteTSDU(context.Background(), b) }()
	go func() {
		defer wg.Done()
		got, err := srv.ReadTSDU(context.Background())
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, a) {
			errs <- errors.New("server got wrong payload")
			return
		}
		errs <- nil
	}()
	go func() {
		defer wg.Done()
		got, err := cli.ReadTSDU(context.Background())
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, b) {
			errs <- errors.New("client got wrong payload")
			return
		}
		errs <- nil
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegration_MultipleSequentialTSDUs(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	for i := 0; i < 5; i++ {
		want := []byte{byte(i), 0xAA, 0xBB}
		errCh := make(chan error, 1)
		var got []byte
		go func() {
			var err error
			got, err = srv.ReadTSDU(context.Background())
			errCh <- err
		}()
		if err := cli.WriteTSDU(context.Background(), want); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("msg %d: got %x want %x", i, got, want)
		}
	}
}

func TestIntegration_SegmentedBothDirections(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 128, MaxTSDULength: 10_000},
		cotp.ServerConfig{MaxTPDULength: 128, MaxTSDULength: 10_000},
	)
	req := bytes.Repeat([]byte{0x11}, 251)  // 3 segments @ 125
	resp := bytes.Repeat([]byte{0x22}, 126) // 2 segments

	// Client ReadTSDU must already be active before the server replies.
	// net.Pipe is synchronous: Write blocks until the peer reads. Waiting for
	// server WriteTSDU to return before starting the client read deadlocks
	// (orchestration bug, not a TP0 segmentation defect).
	type result struct {
		b   []byte
		err error
	}
	clientRead := make(chan result, 1)
	go func() {
		b, err := cli.ReadTSDU(context.Background())
		clientRead <- result{b, err}
	}()

	errCh := make(chan error, 1)
	go func() {
		got, err := srv.ReadTSDU(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, req) {
			errCh <- errors.New("server reassembly mismatch")
			return
		}
		errCh <- srv.WriteTSDU(context.Background(), resp)
	}()
	if err := cli.WriteTSDU(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	res := <-clientRead
	if res.err != nil {
		t.Fatal(res.err)
	}
	if !bytes.Equal(res.b, resp) {
		t.Fatalf("client got len=%d want=%d", len(res.b), len(resp))
	}
}

func TestIntegration_SelectorsAndConnectData(t *testing.T) {
	calling := []byte{0x01, 0x00}
	called := []byte{0x01, 0x01}
	cliData := []byte{0xCA, 0xFE}
	srvData := []byte{0xBE, 0xEF}

	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{
			LocalSelector:  calling,
			RemoteSelector: called,
			MaxTPDULength:  1024,
			ConnectData:    cliData,
		},
		cotp.ServerConfig{
			LocalSelector: called,
			MaxTPDULength: 1024,
			OnConnect: func(_ context.Context, ind cotp.ConnectIndication) (cotp.AcceptDecision, error) {
				if !bytes.Equal(ind.CallingSelector, calling) || !bytes.Equal(ind.CalledSelector, called) {
					return cotp.AcceptDecision{Action: cotp.ConnectReject, RejectReason: cotp.ReasonAddressUnknown}, nil
				}
				if !bytes.Equal(ind.ConnectData, cliData) {
					return cotp.AcceptDecision{Action: cotp.ConnectReject}, nil
				}
				return cotp.AcceptDecision{Action: cotp.ConnectAccept, ConnectData: srvData}, nil
			},
		},
	)
	cn := cli.Negotiated()
	sn := srv.Negotiated()
	if !bytes.Equal(cn.PeerConnectData, srvData) {
		t.Fatalf("client PeerConnectData = %x", cn.PeerConnectData)
	}
	if !bytes.Equal(sn.PeerConnectData, cliData) {
		t.Fatalf("server PeerConnectData = %x", sn.PeerConnectData)
	}
	if cn.LocalRef == 0 || cn.RemoteRef == 0 || sn.LocalRef == 0 || sn.RemoteRef == 0 {
		t.Fatalf("zero refs: client=%+v server=%+v", cn, sn)
	}
	if cn.LocalRef != sn.RemoteRef || cn.RemoteRef != sn.LocalRef {
		t.Fatalf("ref mismatch client=%+v server=%+v", cn, sn)
	}
}

func TestIntegration_SizeProfilePreferredMaximum(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1000, SizeProfile: cotp.SizeProfilePreferredMaximum},
		cotp.ServerConfig{MaxTPDULength: 1000, SizeProfile: cotp.SizeProfilePreferredMaximum},
	)
	// floor(1000/128)*128 = 896 on preferred path.
	if cli.Negotiated().MaxTPDULength != 896 {
		t.Fatalf("client negotiated = %d, want 896", cli.Negotiated().MaxTPDULength)
	}
	if srv.Negotiated().MaxTPDULength != 896 {
		t.Fatalf("server negotiated = %d, want 896", srv.Negotiated().MaxTPDULength)
	}
}

func TestIntegration_SizeProfileCompat1024(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	if cli.Negotiated().MaxTPDULength != 1024 || srv.Negotiated().MaxTPDULength != 1024 {
		t.Fatalf("negotiated client=%d server=%d", cli.Negotiated().MaxTPDULength, srv.Negotiated().MaxTPDULength)
	}
}

func TestIntegration_OnConnectReject(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	errCh := make(chan error, 1)
	go func() {
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
			MaxTPDULength: 1024,
			OnConnect: func(context.Context, cotp.ConnectIndication) (cotp.AcceptDecision, error) {
				return cotp.AcceptDecision{Action: cotp.ConnectReject, RejectReason: cotp.ReasonCongestionAtTSAP}, nil
			},
		})
		errCh <- err
	}()
	_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
	if !errors.Is(err, cotp.ErrConnectionRefused) {
		t.Fatalf("Connect err = %v", err)
	}
	var rej *cotp.RejectionError
	if !errors.As(err, &rej) || rej.Reason != cotp.ReasonCongestionAtTSAP {
		t.Fatalf("RejectionError = %#v", rej)
	}
	if err := <-errCh; !errors.Is(err, cotp.ErrConnectionRefused) {
		t.Fatalf("Accept err = %v", err)
	}
}

func TestIntegration_CloseAndEOF(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	errCh := make(chan error, 1)
	go func() {
		_, err := srv.ReadTSDU(context.Background())
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := cli.Close(); !errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, cotp.ErrDisconnected) || !errors.Is(err, io.EOF) {
			t.Fatalf("server ReadTSDU after peer Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server not unblocked")
	}
}
