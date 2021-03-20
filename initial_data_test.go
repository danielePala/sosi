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
	initTest2Port = 8083
)

// Test 1
// test initial data write with 12500 bytes. Just a random value
// bigger than 10240, so that an OA should be sent in response.
// No error should occur.
func TestWrite12500bytesIn(t *testing.T) {
	writeNbytesIn(t, 12500, initTest1Port)
}

// Test 2
// test initial data write with 125 bytes. Just a random value
// smaller than 10240, so that no OA should be sent in response.
// No error should occur.
func TestWrite125bytesIn(t *testing.T) {
	writeNbytesIn(t, 125, initTest2Port)
}

func writeNbytesIn(t *testing.T, size, port int) {
	// start a server
	go sosiServerReadNbytesIn(t, port, size)
	// wait for server to come up
	time.Sleep(time.Millisecond)
	remAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105:106"
	sosiAddr, err := ResolveSOSIAddr("sosi", remAddr)
	checkErrorIn(err, t)
	// try to connect
	opt := DialOpt{
		ConnID:         ConnID{},
		MaxTSDUSizeOut: 0,
		MaxTSDUSizeIn:  0,
		Data:           make([]byte, size),
	}
	conn, err := DialOptSOSI("sosi", nil, sosiAddr, opt)
	checkErrorIn(err, t)
	// close connection
	err = conn.Close()
	checkErrorIn(err, t)
}

// a sosi server reading size bytes of initial user data. No fault is expected.
func sosiServerReadNbytesIn(t *testing.T, port, size int) {
	locAddr := "127.0.0.1:" + strconv.Itoa(port) + ":105:106"
	sosiAddr, err := ResolveSOSIAddr("sosi", locAddr)
	checkErrorIn(err, t)
	if sosiAddr.String() != locAddr {
		t.Log(sosiAddr.String())
		t.FailNow()
	}
	listener, err := ListenSOSI(sosiAddr.Network(), sosiAddr)
	checkErrorIn(err, t)
	// listen for connections
	conn, data, err := listener.AcceptSOSI()
	checkErrorIn(err, t)
	if len(data) != size {
		t.Log("Wrong data size: ", len(data))
		t.FailNow()
	}
	// close connection
	err = conn.Close()
	checkErrorIn(err, t)
	err = listener.Close()
	checkErrorIn(err, t)
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
