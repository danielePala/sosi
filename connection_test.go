/*
 Copyright 2013-2019 Daniele Pala <pala.daniele@gmail.com>

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
 along with sosi. If not, see <http://www.gnu.org/licenses/>.

*/

package sosi

import (
	"strconv"
	"testing"
	"time"
)

const (
	// each test uses different ports for servers,
	// in order to avoid possible conflicts.
	connTest1Port = 8080
)

// Test 1
// test connection establishment and closing. No error should occur.
func TestConn(t *testing.T) {
	// start a server
	go sosiServer(t, connTest1Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(connTest1Port) + ":105:106"
	sosiAddr, err := ResolveSOSIAddr("sosi", remAddr)
	checkError(err, t)
	// try to connect
	conn, err := DialSOSI("sosi", nil, sosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// Test 2
// test connection establishment and closing.
// Don't specify any tsel. No error should occur.
func TestConnNoTsel(t *testing.T) {
	// start a server
	go sosiServerNoTsel(t)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1:::106")
	checkError(err, t)
	if sosiAddr.String() != "127.0.0.1:102::106" {
		t.Log(sosiAddr.String())
		t.FailNow()
	}
	// try to connect
	conn, err := DialSOSI("sosi", nil, sosiAddr)
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
}

// a sosi server. No fault is expected.
func sosiServer(t *testing.T, port int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105:106"
	sosiAddr, err := ResolveSOSIAddr("sosi", locAddr)
	checkError(err, t)
	if sosiAddr.String() != locAddr {
		t.Log(sosiAddr.String())
		t.FailNow()
	}
	listener, err := ListenSOSI(sosiAddr.Network(), sosiAddr)
	checkError(err, t)
	// listen for connections
	conn, err := listener.Accept()
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// a sosi server with no tsel. No fault is expected.
func sosiServerNoTsel(t *testing.T) {
	sosiAddr, err := ResolveSOSIAddr("sosi", "127.0.0.1:::106")
	checkError(err, t)
	listener, err := ListenSOSI("sosi", sosiAddr)
	checkError(err, t)
	// listen for connections
	conn, err := listener.Accept()
	checkError(err, t)
	// close connection
	err = conn.Close()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// check for unexpected errors
func checkError(err error, t *testing.T) {
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// check for expected errors
func checkWantedError(err error, t *testing.T) {
	if err == nil {
		t.FailNow()
	}
}
