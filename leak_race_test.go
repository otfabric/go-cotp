// SPDX-License-Identifier: MIT

package cotp_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-cotp"
)

func TestLeak_CloseUnblocksConnect(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	errCh := make(chan error, 1)
	go func() {
		_, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{MaxTPDULength: 1024})
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond)
	_ = c2.Close() // peer reset while Connect awaits CC
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Connect succeeded after peer close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Connect not unblocked")
	}
}

func TestLeak_CloseUnblocksAccept(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	errCh := make(chan error, 1)
	go func() {
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
		errCh <- err
	}()
	time.Sleep(30 * time.Millisecond)
	_ = c1.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Accept succeeded after peer close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept not unblocked")
	}
}

func TestLeak_CloseUnblocksReadTSDU(t *testing.T) {
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
	if err := srv.Close(); !errors.Is(err, cotp.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("ReadTSDU succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadTSDU not unblocked")
	}
	_ = cli.Close()
}

func TestLeak_CloseUnblocksWriteTSDU(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 128},
		cotp.ServerConfig{MaxTPDULength: 128},
	)
	// Do not read on the peer so the writer's pipe fills and blocks.
	errCh := make(chan error, 1)
	go func() {
		errCh <- cli.WriteTSDU(context.Background(), make([]byte, 64*1024))
	}()
	time.Sleep(30 * time.Millisecond)
	if err := cli.Close(); !errors.Is(err, cotp.ErrClosed) {
		// May already be aborted by peer/stream; either way write must unblock.
		if err == nil {
			t.Fatal("Close returned nil unexpectedly without ErrClosed")
		}
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("WriteTSDU succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTSDU not unblocked")
	}
	_ = srv.Close()
}

func TestLeak_TimeoutGoroutineExits(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := srv.ReadTSDU(ctx)
	if err == nil {
		t.Fatal("expected timeout")
	}
	// Subsequent ops must see a terminal connection (context expiry after I/O aborts).
	if err2 := srv.WriteTSDU(context.Background(), []byte{1}); err2 == nil {
		t.Fatal("write succeeded after deadline abort")
	}
	_ = cli.Close()
}

func TestLeak_CallbackBlockedPeerCloses(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	entered := make(chan struct{})
	release := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
			MaxTPDULength: 1024,
			OnConnect: func(context.Context, cotp.ConnectIndication) (cotp.AcceptDecision, error) {
				close(entered)
				<-release
				return cotp.AcceptDecision{Action: cotp.ConnectAccept}, nil
			},
		})
		errCh <- err
	}()

	// Valid CR so Accept enters OnConnect; peer closes while callback is blocked.
	go func() {
		writePeerTPDU(t, c1, mustMarshalTPDU(t, &cotp.CR{SourceRef: 9, TPDUSize: u8(0x0A)}))
		<-entered
		_ = c1.Close()
		close(release)
	}()

	select {
	case err := <-errCh:
		// Accept may fail writing CC after peer close, or succeed if the write
		// raced; either way it must return and not hang.
		_ = err
	case <-time.After(3 * time.Second):
		t.Fatal("Accept not unblocked after callback + peer close")
	}
}

func TestLeak_ReadFailureRacesLocalClose(t *testing.T) {
	cli, srv := openTP0Pair(t,
		cotp.ClientConfig{MaxTPDULength: 1024},
		cotp.ServerConfig{MaxTPDULength: 1024},
	)
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, err := srv.ReadTSDU(context.Background())
		errs <- err
	}()
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		errs <- srv.Close()
	}()
	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = cli.Close() // peer EOF racing local Close
	}()
	wg.Wait()
	close(errs)
	var saw error
	for err := range errs {
		if err != nil {
			saw = err
		}
	}
	if saw == nil {
		t.Fatal("expected at least one terminal error")
	}
	// First terminal cause is sticky.
	if err := srv.WriteTSDU(context.Background(), []byte{1}); err == nil {
		t.Fatal("write succeeded after terminal race")
	}
}

func TestLeak_NoPipeGoroutineHangOnHandshakeFail(t *testing.T) {
	// Rapid failed handshakes should not leave blocked peer goroutines.
	for i := 0; i < 20; i++ {
		c1, c2 := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer func() { _ = c1.Close() }()
			writePeerTPDU(t, c1, []byte{0x02, 0x00, 0x00})
			buf := make([]byte, 1)
			_, _ = c1.Read(buf)
		}()
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
		if err == nil {
			t.Fatal("expected Accept failure")
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: peer goroutine leaked", i)
		}
	}
}
