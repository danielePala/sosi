/*
 Copyright 2014 Daniele Pala <pala.daniele@gmail.com>

 This file is part of sosi.

 sosi is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 sosi is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with   If not, see <http://www.gnu.org/licenses/>.

*/

package sosi

import (
	"bytes"
	"testing"
	"time"
)

// Test 1
// test data write with 2 bytes.
// No error should occur.
func TestWrite2bytes(t *testing.T) {
	testPayloads(t, DialOpt{}, []byte{0x01, 0x02})
}

// Test 2
// test data write with 2 bytes and maximum size of 1 byte.
// It should fail.
func TestWrite2bytesFail(t *testing.T) {
	testPayloadsFail(t, DialOpt{MaxTSDUSizeOut: 1}, []byte{0x01, 0x02})
}

// send a given set of payloads as a single message
func testPayloads(t *testing.T, opt DialOpt, payloads ...[]byte) {
	var allPayloads []byte
	for _, payload := range payloads {
		allPayloads = append(allPayloads, payload...)
	}
	// start a server
	go sosiServerReadPayloads(t, opt, payloads...)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1::105:106")
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialOptSOSI("sosi", nil, sosiAddr, opt)
	defer cleanup(t, conn, nil)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	_, err = conn.Write(allPayloads)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// send a given set of payloads as a single message. Expects to fail.
func testPayloadsFail(t *testing.T, opt DialOpt, payloads ...[]byte) {
	var allPayloads []byte
	for _, payload := range payloads {
		allPayloads = append(allPayloads, payload...)
	}
	// start a server
	go sosiServerReadPayloadsFail(t, opt, allPayloads)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1::105:106")
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	// try to connect
	conn, err := DialOptSOSI("sosi", nil, sosiAddr, opt)
	defer cleanup(t, conn, nil)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	_, err = conn.Write(allPayloads)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	if err == nil {
		t.FailNow()
	}
	time.Sleep(time.Millisecond)
}

// a sosi server reading arbitrary payloads. No fault is expected.
func sosiServerReadPayloads(t *testing.T, opt DialOpt, payloads ...[]byte) {
	var conn *SOSIConn
	var listener *SOSIListener
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1::105:106")
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenSOSI("sosi", sosiAddr)
	if err != nil {
		cleanup(t, nil, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	// listen for connections
	c, err := listener.Accept()
	conn = c.(*SOSIConn)
	defer cleanup(t, conn, listener)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	totalSize := 0
	for _, payload := range payloads {
		size := len(payload)
		totalSize += size
		buf := make([]byte, size)
		read, err := conn.Read(buf)
		if err != nil {
			t.Log(err.Error())
			t.FailNow()
		}
		if read != size {
			t.Log("Wrong data size")
			t.FailNow()
		}
		if !bytes.Equal(buf[:], payload) {
			t.Log("Wrong data values")
			t.FailNow()
		}
	}
}

// a sosi server reading arbitrary payloads. A fault is expected.
func sosiServerReadPayloadsFail(t *testing.T, opt DialOpt, payload []byte) {
	var conn *SOSIConn
	var listener *SOSIListener
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1::105:106")
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	listener, err = ListenSOSI("sosi", sosiAddr)
	if err != nil {
		cleanup(t, nil, listener)
		t.Log(err.Error())
		t.FailNow()
	}
	// listen for connections
	c, err := listener.Accept()
	conn = c.(*SOSIConn)
	defer cleanup(t, conn, listener)
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
	size := len(payload)
	buf := make([]byte, size)
	_, err = conn.Read(buf)
	if err == nil {
		t.FailNow()
	}
}

// a cleanup utility function
func cleanup(t *testing.T, conn *SOSIConn, listener *SOSIListener) {
	var err error
	if conn != nil { // close connection
		err = conn.Close()
		if err != nil {
			t.Log(err.Error())
			t.Fail()
		}
	}
	if listener != nil { // close listener
		err = listener.Close()
		if err != nil {
			t.Log(err.Error())
			t.Fail()
		}
	}
}
