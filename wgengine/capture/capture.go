// Copyright (c) 2023 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

func writePcapHeader(w io.Writer) {
	binary.Write(w, binary.LittleEndian, uint32(0xA1B2C3D4)) // pcap magic number
	binary.Write(w, binary.LittleEndian, uint16(2))          // version major
	binary.Write(w, binary.LittleEndian, uint16(4))          // version minor
	binary.Write(w, binary.LittleEndian, uint32(0))          // this zone
	binary.Write(w, binary.LittleEndian, uint32(0))          // zone significant figures
	binary.Write(w, binary.LittleEndian, uint32(65535))      // max packet len
	binary.Write(w, binary.LittleEndian, uint32(147))        // link-layer ID
}

func writePktHeader(w *bytes.Buffer, when time.Time, length int) {
	s := when.Unix()
	us := when.UnixMicro() - (s * 1000000)

	binary.Write(w, binary.LittleEndian, uint32(s))      // timestamp in seconds
	binary.Write(w, binary.LittleEndian, uint32(us))     // timestamp microseconds
	binary.Write(w, binary.LittleEndian, uint32(length)) // length present
	binary.Write(w, binary.LittleEndian, uint32(length)) // total length
}

// Path describes where in the data path the packet was captured.
type Path uint8

// Valid Path values.
const (
	FromLocal Path = iota
	FromPeer
	SynthesizedToLocal
	SynthesizedToPeer
)

func TCPSink(addr string) (*Sink, error) {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	l, err := net.ListenTCP("tcp", a)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	s := &Sink{
		close:     make(chan struct{}),
		listeners: []net.Listener{l},
	}

	go func() {
		<-s.close
		l.Close()
	}()
	go func() {
		for {
			select {
			case <-s.close:
				return
			default:
				conn, err := l.AcceptTCP()
				if err != nil {
					fmt.Println(err)
					return
				}
				conn.SetKeepAlive(true)
				conn.SetNoDelay(false)
				writePcapHeader(conn)

				s.mu.Lock()
				s.outputs = append(s.outputs, conn)
				s.mu.Unlock()
			}
		}
	}()

	return s, nil
}

// Type Sink handles callbacks with packets to be logged,
// and formats them into a pcap for streaming.
type Sink struct {
	close chan struct{}

	mu        sync.Mutex
	listeners []net.Listener
	outputs   []io.WriteCloser
}

func (s *Sink) Close() error {
	close(s.close)
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, o := range s.outputs {
		o.Close()
	}
	s.outputs = nil
	return nil
}

// LogPacket is called to insert a packet into the capture.
func (s *Sink) LogPacket(path Path, when time.Time, data []byte) {
	b := bytes.NewBuffer(make([]byte, 0, 16+2+len(data)))
	writePktHeader(b, when, len(data)+2)
	// Custom tailscale debugging data
	binary.Write(b, binary.LittleEndian, uint16(path))
	b.Write(data)

	s.mu.Lock()
	defer s.mu.Unlock()

	var hadError []int
	for i, o := range s.outputs {
		if _, err := o.Write(b.Bytes()); err != nil {
			hadError = append(hadError, i)
		}
	}

	for i, outputIdx := range hadError {
		idx := outputIdx - i
		s.outputs[idx].Close()
		s.outputs = append(s.outputs[:idx], s.outputs[idx+1:]...)
	}
}
