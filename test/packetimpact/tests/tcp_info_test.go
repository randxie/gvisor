// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_info

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestTCPInfo(t *testing.T) {
	// Create a socket, listen, TCP connect, and accept.
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	conn.Connect(t)
	acceptFD, _ := dut.Accept(t, listenFD)

	defer conn.Close(t)
	defer dut.Close(t, listenFD)

	// Send and receive sample data.
	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}
	dut.Send(t, acceptFD, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})

	info := linux.TCPInfo{}
	ret := dut.GetSockOpt(t, acceptFD, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	binary.Unmarshal(ret, usermem.ByteOrder, &info)

	rtt := time.Duration(info.RTT) * time.Microsecond
	rttvar := time.Duration(info.RTTVar) * time.Microsecond
	rto := time.Duration(info.RTO) * time.Microsecond
	if rtt == 0 || rttvar == 0 || rto == 0 {
		t.Fatalf("expected rtt, rttvar and rto to be greater than zero")
	}
	if info.ReordSeen != 0 {
		t.Fatalf("expected the connection to not have any reordering, got: %v want: 0", info.ReordSeen)
	}
	if info.SndCwnd == 0 {
		t.Fatalf("expected send congestion window to be greater than zero")
	}
	if info.CaState != 0 /* Open */ {
		t.Fatalf("expected the connection to be in open state, got: %v want: 0", info.CaState)
	}

	// Check the congestion control state and send congestion window after
	// retransmission timeout.
	dut.Send(t, acceptFD, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	time.Sleep(rto)

	info1 := linux.TCPInfo{}
	ret1 := dut.GetSockOpt(t, acceptFD, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	binary.Unmarshal(ret1, usermem.ByteOrder, &info1)
	if info1.CaState != 4 /* Loss Recovery */ {
		t.Fatalf("expected the connection to be in loss recovery, got: %v want: 4 %v", info1.CaState)
	}
	if info1.SndCwnd != 1 {
		t.Fatalf("expected send congestion window to be 1, got: %v %v", info1.SndCwnd)
	}
}
