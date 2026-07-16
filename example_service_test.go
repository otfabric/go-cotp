// SPDX-License-Identifier: MIT

package cotp_test

import (
	"context"
	"fmt"
	"net"

	"github.com/otfabric/go-cotp"
)

// ExampleConnect shows a TP0 client over an already-established stream
// (here: net.Pipe; in production: TCP or TLS).
func ExampleConnect() {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	go func() {
		srv, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{MaxTPDULength: 1024})
		if err != nil {
			return
		}
		defer func() { _ = srv.Close() }()
		_, _ = srv.ReadTSDU(context.Background())
	}()

	cli, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{
		LocalSelector:  []byte{0x01, 0x00},
		RemoteSelector: []byte{0x01, 0x01},
		MaxTPDULength:  1024,
	})
	if err != nil {
		fmt.Println("Connect:", err)
		return
	}
	defer func() { _ = cli.Close() }()
	fmt.Println("negotiated", cli.Negotiated().MaxTPDULength)
	_ = cli.WriteTSDU(context.Background(), []byte("hello"))
	// Output: negotiated 1024
}

// ExampleAccept_onConnect shows server selector policy via OnConnect.
func ExampleAccept_onConnect() {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	errCh := make(chan error, 1)
	go func() {
		_, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
			LocalSelector: []byte{0x01, 0x01},
			MaxTPDULength: 1024,
			OnConnect: func(_ context.Context, ind cotp.ConnectIndication) (cotp.AcceptDecision, error) {
				if len(ind.CallingSelector) == 0 {
					return cotp.AcceptDecision{Action: cotp.ConnectReject, RejectReason: cotp.ReasonAddressUnknown}, nil
				}
				return cotp.AcceptDecision{Action: cotp.ConnectAccept}, nil
			},
		})
		errCh <- err
	}()

	cli, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{
		LocalSelector:  []byte{0x01, 0x00},
		RemoteSelector: []byte{0x01, 0x01},
		MaxTPDULength:  1024,
	})
	if err != nil {
		fmt.Println("Connect:", err)
		return
	}
	defer func() { _ = cli.Close() }()
	if err := <-errCh; err != nil {
		fmt.Println("Accept:", err)
		return
	}
	fmt.Println("accepted")
	// Output: accepted
}

// ExampleConn_WriteTSDU_segmentation transfers a TSDU larger than one DT segment.
func ExampleConn_WriteTSDU_segmentation() {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	done := make(chan int, 1)
	go func() {
		srv, err := cotp.Accept(context.Background(), c2, cotp.ServerConfig{
			MaxTPDULength: 128,
			MaxTSDULength: 10_000,
		})
		if err != nil {
			done <- -1
			return
		}
		defer func() { _ = srv.Close() }()
		tsdu, err := srv.ReadTSDU(context.Background())
		if err != nil {
			done <- -1
			return
		}
		done <- len(tsdu)
	}()

	cli, err := cotp.Connect(context.Background(), c1, cotp.ClientConfig{
		MaxTPDULength: 128,
		MaxTSDULength: 10_000,
	})
	if err != nil {
		fmt.Println("Connect:", err)
		return
	}
	defer func() { _ = cli.Close() }()
	payload := make([]byte, 251) // 3 segments @ 125 user octets
	if err := cli.WriteTSDU(context.Background(), payload); err != nil {
		fmt.Println("WriteTSDU:", err)
		return
	}
	fmt.Println("reassembled", <-done)
	// Output: reassembled 251
}
