/*
 Definition of the external interface of the package, based on the
 constructs defined in the standard 'net' package.

 Copyright 2014-2019 Daniele Pala <pala.daniele@gmail.com>

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
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
	"tosi"
)

// DialOpt contains options to be used by the DialOptSOSI function during
// connection establishment. In particular, it contains: A Connection Identifier
// parameter group to enable the identification of the session connection, the
// maximum TSDU size for both directions of transfer, and initial user data
// to be sent during connection establishment.
type DialOpt struct {
	ConnID                // Connection Identifier variables
	MaxTSDUSizeOut uint16 // max TSDU size from local to remote
	MaxTSDUSizeIn  uint16 // max TSDU size from remote to local
	Data           []byte // initial user data
}

// SOSIConn is an implementation of the net.Conn interface
// for SOSI network connections. If the parameter 'Reused' is true,
// than the structure represents a transport connection which has
// been kept open for reuse.
type SOSIConn struct {
	Duplex         bool          // Is this a duplex connection?
	Reused         bool          // Is this a connection kept for reuse?
	MaxTSDUSizeOut uint16        // max TSDU size from initiator to responder
	MaxTSDUSizeIn  uint16        // max TSDU size from responder to initiator
	Token          int           // token status
	laddr, raddr   SOSIAddr      // local and remote address
	vn             byte          // selected version number
	tosiConn       tosi.TOSIConn // TOSI connection
	userData                     // read buffer
}

// structure holding data from TOSI which hasn't been returned to the user yet
type userData struct {
	readBuf   []byte // read buffer
	endOfSSDU bool   // is this data the last part of an SSDU?
}

// SOSIAddr represents the address of a SOSI end point.
type SOSIAddr struct {
	tosi.TOSIAddr        // TOSI address
	Ssel          []byte // session selector (optional)
}

// SOSIListener is a SOSI network listener. Clients should typically use
// variables of type net.Listener instead of assuming SOSI.
type SOSIListener struct {
	addr         *SOSIAddr
	tosiListener tosi.TOSIListener
}

// DialSOSI connects to the remote address raddr on the network net, which must
// be "sosi", "sosi4", or "sosi6".
// If loc is not nil, it is used as the local address for the connection.
func DialSOSI(net string, loc, rem *SOSIAddr) (*SOSIConn, error) {
	return DialOptSOSI(net, loc, rem, DialOpt{})
}

// RedialSOSI connects to a remote endpoint by reusing an already
// existing connection.
func RedialSOSI(reused *SOSIConn, op DialOpt) (*SOSIConn, error) {
	cv := parseOptions(&reused.laddr, &reused.raddr, op)
	return dial(&reused.tosiConn, &reused.laddr, &reused.raddr, cv)
}

// DialOptSOSI is the same as DialSOSI, but it takes an additional 'options'
// parameter.
func DialOptSOSI(snet string, loc, rem *SOSIAddr, op DialOpt) (*SOSIConn, error) {
	if rem == nil {
		return nil, errors.New("invalid remote address")
	}
	TOSInet := sosiToTOSInet(snet)
	var tosiLaddr *tosi.TOSIAddr
	if loc != nil {
		tosiLaddr = &loc.TOSIAddr
	} else {
		tosiLaddr = nil
	}
	// try to establish a TOSI connection
	tconn, err := tosi.DialTOSI(TOSInet, tosiLaddr, &rem.TOSIAddr)
	if err != nil {
		return nil, err
	}
	cv := parseOptions(loc, rem, op)
	return dial(tconn, loc, rem, cv)
}

// setup ISO connection vars
func parseOptions(loc, rem *SOSIAddr, op DialOpt) (cv cnVars) {
	cv.ConnID = op.ConnID // Connection Identifier
	if len(cv.ConnID.SSUsrRef) > urMaxLen {
		op.ConnID.SSUsrRef = op.ConnID.SSUsrRef[:urMaxLen]
	}
	if len(cv.ConnID.ComRef) > crMaxLen {
		op.ConnID.ComRef = op.ConnID.ComRef[:crMaxLen]
	}
	if len(cv.ConnID.RefInfo) > infoMaxLen {
		op.ConnID.RefInfo = op.ConnID.RefInfo[:infoMaxLen]
	}
	cv.protOpt = poExtendedConc // Protocol Options
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, op.MaxTSDUSizeOut)
	binary.Write(buf, binary.BigEndian, op.MaxTSDUSizeIn)
	copy(cv.maxTSDUSize[:], buf.Bytes()) // TSDU maximum size
	cv.version = vnTwo                   // Version Number
	cv.sesUserReq[1] = surValue          // Session User Requirements
	if loc != nil {
		cv.locSSEL = loc.Ssel // Calling Session Selector
	}
	cv.remSSEL = rem.Ssel // Called Session Selector
	cv.userData = op.Data // User Data / Extended User Data
	if len(cv.userData) <= udMaxLen {
		cv.version += vnOne
	} else if len(cv.userData) > udMaxExt {
		cv.dataOverflow = true // Data Overflow
		cv.ovfData = cv.userData[udMaxLen:]
		cv.userData = cv.userData[:udMaxLen]
	}
	return
}

// dial opens a session with the remote address rem using the transport
// connection t. If loc is not nil, it is used as the local address
// for the session connection. The parameters of the connection request
// are taken as inputs from the caller.
func dial(t *tosi.TOSIConn, loc, rem *SOSIAddr, cv cnVars) (*SOSIConn, error) {
	_, err := t.Write(cn(cv)) // send a CN
	if err != nil {
		return nil, err
	}
	// try to read a TSDU in response
	tsdu, _, err := t.ReadTSDU()
	if err != nil {
		return nil, err
	}
	// REFUSE SPDU
	if isRF(tsdu) {
		err = errors.New("Connection request refused")
		valid, v := validateRF(tsdu, 0)
		if !valid {
			t.Close()
			return nil, err
		}
		if v.tdisc == 0 {
			reused := &SOSIConn{
				Reused:   true,
				tosiConn: *t,
				raddr:    *rem}
			if loc != nil {
				reused.laddr = *loc
			}
			return reused, err
		} else {
			t.Close()
			return nil, err
		}
	}
	if cv.dataOverflow {
		// OVERFLOW ACCEPT SPDU
	} else {
		// ACCEPT SPDU
		if isAC(tsdu) {
			// process AC
			c, err := handleAC(tsdu, t, cv)
			if err != nil {
				return c, err
			}
			if loc == nil {
				var tosiAddr = t.LocalAddr().(*tosi.TOSIAddr)
				c.laddr.TOSIAddr = *tosiAddr
			} else {
				c.laddr = *loc
			}
			c.raddr = *rem
			return c, err
		}
	}
	return nil, err
}

// parse an AC, handling errors
func handleAC(tsdu []byte, tconn *tosi.TOSIConn, cv cnVars) (*SOSIConn, error) {
	// we have an AC, check if it is valid
	valid, av := validateAC(tsdu, cv)
	if !valid {
		// we got an invalid AC
		// refuse the connection
		tconn.Close()
		return nil, errors.New("received an invalid AC")
	}
	// all ok, connection established
	sconn := createSessionConn(cv, av)
	sconn.tosiConn = *tconn
	return sconn, nil
}

// convert a SOSI net to a TOSI net.
func sosiToTOSInet(sosi string) (tosi string) {
	switch sosi {
	case "sosi":
		tosi = "tosi"
	case "sosi4":
		tosi = "tosi4"
	case "sosi6":
		tosi = "tosi6"
	default:
		tosi = ""
	}
	return
}

// Network returns the address's network name, "sosi".
func (a *SOSIAddr) Network() string {
	return "sosi"
}

func (a *SOSIAddr) String() string {
	return a.TOSIAddr.String() + ":" + string(a.Ssel)
}

// ResolveSOSIAddr parses addr as a SOSI address of the form tosi:ssel and
// resolves domain names to numeric addresses on the network snet,
// which must be "sosi", "sosi4" or "sosi6".
// The tosi part must be a valid TOSI address of the form tcp:tsel, enclosed
// in square brackets, as in [[127.0.0.1:80]:20].
// A literal IPv6 host address must be enclosed in square brackets,
// as in "[::]:80". ssel is the "session selector", which can be an arbitrary
// sequence of bytes. Thus '[[127.0.0.1:80]:20]:hello' is a valid address.
func ResolveSOSIAddr(snet, addr string) (sosiAddr *SOSIAddr, err error) {
	// after the last ':' we have the SSEL
	index := strings.LastIndex(addr, ":")
	if index < 0 {
		return nil, errors.New("invalid address")
	}
	tAddr := addr[:index]
	var ssel string
	if len(addr) > (index + 1) {
		ssel = addr[index+1:]
	}
	tosiNet := sosiToTOSInet(snet)
	tosiAddr, err := tosi.ResolveTOSIAddr(tosiNet, tAddr)
	if err != nil {
		return nil, err
	}
	sosiAddr = &SOSIAddr{TOSIAddr: *tosiAddr}
	if ssel != "" {
		sosiAddr.Ssel = []byte(ssel)
	}
	return sosiAddr, nil
}

// Close closes the SOSI connection.
// TODO: implement the closing sequence.
func (c *SOSIConn) Close() error {
	return c.tosiConn.Close()
}

// LocalAddr returns the local network address.
func (c *SOSIConn) LocalAddr() net.Addr {
	return &c.laddr
}

// Read implements the net.Conn Read method.
// TODO: implement this
func (c *SOSIConn) Read(b []byte) (n int, err error) {
	if b == nil {
		return
	}
	// see if there's something in the read buffer
	if c.readBuf != nil {
		copy(b, c.readBuf)
		if len(b) < len(c.readBuf) {
			// Cannot return the whole SDU
			n = len(b)
			c.readBuf = c.readBuf[len(b):]
		} else {
			n = len(c.readBuf)
			c.readBuf = nil
		}
		return n, nil
	}
	// try to read a GT+DT
	tsdu, _, err := c.tosiConn.ReadTSDU()
	if err != nil {
		return 0, err
	}
	if c.MaxTSDUSizeIn > 0 {
		if len(tsdu) > int(c.MaxTSDUSizeIn) {
			return 0, err
		}
	}
	dt := getData(tsdu)
	if dt == nil {
		c.tosiConn.Write(ab(1, 0, nil, nil))
	}
	copy(b, dt)
	return len(dt), nil
}

// RemoteAddr returns the remote network address.
func (c *SOSIConn) RemoteAddr() net.Addr {
	return &c.raddr
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *SOSIConn) SetDeadline(t time.Time) error {
	return c.tosiConn.SetDeadline(t)
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *SOSIConn) SetReadDeadline(t time.Time) error {
	return c.tosiConn.SetReadDeadline(t)
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *SOSIConn) SetWriteDeadline(t time.Time) error {
	return c.tosiConn.SetWriteDeadline(t)
}

// Write implements the net.Conn Write method.
// Segmenting of SSDUs takes place under the following circumstances:
//   a) when a maximum TSDU size has been selected, in which case a data SSDU
//      or a typed data SSDU may be mapped onto more than one SPDU;
//   b) when Protocol Version 2 is proposed or selected and either:
//     1) the SPDU size would exceed the maximum TSDU size; or
//     2) the SPDU size would exceed 65539 octets for an SPDU to be sent on the
//        transport normal flow or 16 octets for an SPDU to be sent on the
//        transport expedited flow, in which case SSDUs other than data SSDUs,
//        typed data SSDUs and expedited data SSDUs are mapped onto more than
//        one SPDU.
// In all other cases, each SSDU is mapped one-to-one onto an SPDU.
func (c *SOSIConn) Write(b []byte) (n int, err error) {
	if b == nil {
		return
	}
	bufLen := len(b)
	var maxWrite int
	if c.MaxTSDUSizeOut > 0 {
		maxWrite = int(c.MaxTSDUSizeOut)
	} else {
		maxWrite = bufLen
	}
	// if b is too big, split it into smaller chunks
	if bufLen > maxWrite {
		encItem := eiBegin
		numWrites := (bufLen / maxWrite)
		if (bufLen % maxWrite) > 0 {
			numWrites += 1
		}
		for i := 0; i < numWrites; i++ {
			if i == (numWrites - 1) {
				encItem = eiEnd
			}
			start := maxWrite * i
			end := maxWrite * (i + 1)
			if end > bufLen {
				end = bufLen
			}
			var part []byte
			if c.Duplex == true {
				part = dt(true, encItem, b[start:end])
			} else {
				part = append(gt(0, 0, nil), dt(true, encItem, b[start:end])...)
			}
			nPart, err := c.tosiConn.Write(part)
			n = n + nPart
			if err != nil {
				return n, err
			}
			encItem = eiMiddle
		}
		return
	}
	return c.tosiConn.Write(append(gt(0, 0, nil), dt(false, eiBegin, b)...))
}

// ListenSOSI announces on the SOSI address loc and returns a SOSI listener.
// snet must be "sosi", "sosi4", or "sosi6".
func ListenSOSI(snet string, loc *SOSIAddr) (*SOSIListener, error) {
	if loc == nil {
		return nil, errors.New("invalid local address")
	}
	tosiAddr := loc.TOSIAddr
	tosiNet := sosiToTOSInet(snet)
	listener, err := tosi.ListenTOSI(tosiNet, &tosiAddr)
	if err != nil {
		return nil, err
	}
	return &SOSIListener{addr: loc, tosiListener: *listener}, nil
}

// Accept implements the Accept method in the net.Listener interface;
// it waits for the next call and returns a generic net.Conn.
func (l *SOSIListener) Accept() (net.Conn, error) {
	// listen for TOSI connections
	tconn, err := l.tosiListener.AcceptTOSI(nil)
	if err != nil {
		return nil, err
	}
	// try to read a CN
	tsdu, _, err := tconn.ReadTSDU()
	if err != nil {
		return nil, err
	}
	if isCN(tsdu) {
		sosi, err := cnReply(*l.addr, tsdu, *tconn)
		return &sosi, err
	}
	tconn.Close()
	if err == nil {
		err = errors.New("received an invalid TSDU")
	}
	return nil, err
}

// parse a CN, handling errors and sending an AC in response.
func cnReply(addr SOSIAddr, tsdu []byte, t tosi.TOSIConn) (SOSIConn, error) {
	var reply []byte
	var repCv acVars
	valid, cv := validateCN(tsdu, addr.Ssel)
	if valid {
		if cv.sesUserReq[1]&duplex == duplex {
			repCv.sesUserReq[1] = duplex
		} else {
			repCv.sesUserReq[1] = halfDuplex
		}
		if cv.version == vnOne {
			repCv.version = vnOne
		} else {
			repCv.version = vnTwo
			// The Enclosure Item parameter, if present, shall indicate that the
			// SPDU is the beginning, but not end of the SSDU. This parameter
			// shall not be present if Protocol Version 1 is selected.
			repCv.enclItem = eiBegin
		}
		reply = ac(repCv) // reply with an AC
	} else {
		// reply with a REFUSE
	}
	_, err := t.Write(reply)
	if valid && (err == nil) {
		var MaxTSDUSizeIn uint16
		buf := bytes.NewReader(cv.maxTSDUSize[0:2])
		_ = binary.Read(buf, binary.BigEndian, &MaxTSDUSizeIn)
		return SOSIConn{
			MaxTSDUSizeIn: MaxTSDUSizeIn,
			tosiConn:      t,
			laddr:         addr}, nil
	}
	t.Close()
	if err == nil {
		err = errors.New("received an invalid CN")
	}
	return SOSIConn{}, err
}

// Addr returns the listener's network address.
func (l *SOSIListener) Addr() net.Addr {
	return l.addr
}

// Close stops listening on the SOSI address.
// Already Accepted connections are not closed.
func (l *SOSIListener) Close() error {
	return l.tosiListener.Close()
}
