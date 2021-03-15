package sosi

import (
	"strconv"
	"testing"
	"time"
)

const (
	// each test uses different ports for servers,
	// in order to avoid possible conflicts.
	initTest1Port = 8082
)

// Test 1
// test initial data write with 12500 bytes. Just a random value
// bigger than 10240, so that an OA should be sent in response.
// No error should occur.
func TestWrite12500bytesIn(t *testing.T) {
	// start a server
	go sosiServerRead12500bytesIn(t, initTest1Port)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(initTest1Port) + ":105:106"
	sosiAddr, err := ResolveSOSIAddr("sosi", remAddr)
	checkError(err, t)
	// try to connect
	opt := DialOpt{
		ConnID:         ConnID{},
		MaxTSDUSizeOut: 0,
		MaxTSDUSizeIn:  0,
		Data:           make([]byte, 12500),
	}
	conn, err := DialOptSOSI("sosi", nil, sosiAddr, opt)
	checkErrorIn(err, t)
	// close connection
	err = conn.Close()
	checkErrorIn(err, t)
}

// a sosi server reading 12500 bytes of initial user data. No fault is expected.
func sosiServerRead12500bytesIn(t *testing.T, port int) {
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
	conn, data, err := listener.AcceptSOSI()
	checkError(err, t)
	if len(data) != 12500 {
		t.Log("Wrong data size")
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkError(err, t)
	err = listener.Close()
	checkError(err, t)
}

// check for unexpected errors
func checkErrorIn(err error, t *testing.T) {
	if err != nil {
		t.Log(err.Error())
		t.FailNow()
	}
}

// check for expected errors
func checkWantedErrorIn(err error, t *testing.T) {
	if err == nil {
		t.FailNow()
	}
}
