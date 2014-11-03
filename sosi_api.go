package sosi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	MaxTSDUSizeOut uint16 // max TSDU size from initiator to responder
	MaxTSDUSizeIn  uint16 // max TSDU size from responder to initiator
	Data           []byte // initial user data
}

// SOSIConn is an implementation of the net.Conn interface
// for SOSI network connections. If the parameter 'Reused' is true,
// than the structure represents a transport connection which has
// been kept open for reuse.
type SOSIConn struct {
	Reused       bool          // Is this a connection kept for reuse?
	MaxTSDUSizeOut uint16      // max TSDU size from initiator to responder
	MaxTSDUSizeIn  uint16      // max TSDU size from responder to initiator
	laddr, raddr SOSIAddr      // local and remote address
	vn byte                    // selected version number
	tosiConn     tosi.TOSIConn // TOSI connection
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
		if !validateRF(tsdu, 0) {
			t.Close()
			return nil, err 
		}
		v := decodeRF(tsdu)
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
	valid := validateAC(tsdu, cv)
	if !valid {
		// we got an invalid AC
		// refuse the connection
		tconn.Close()
		return nil, errors.New("received an invalid AC")
	}
	//repCv := decodeAC(tsdu)
	// all ok, connection established
	return &SOSIConn{tosiConn: *tconn}, nil
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
	fmt.Printf("transport: %v, ssel: %v, err: %v\n", tAddr, ssel, err)
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
	ok := readGT()
	if ok {
		readDT()
	}
	n, err = c.tosiConn.Read(b)
	return
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
// TODO: implement this
func (c *SOSIConn) Write(b []byte) (n int, err error) {
	return c.tosiConn.Write(append(gt(0,0,nil), dt(3, b)...))
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
	fmt.Printf("received: %v\n", cv)
	if valid {
		// reply with an AC
		reply = ac(repCv)
		fmt.Printf("Sending AC... %v\n", reply)
	} else {
		// reply with a REFUSE
	}
	_, err := t.Write(reply)
	if valid && (err == nil) {
		return SOSIConn{
			tosiConn: t,
			laddr:    addr}, nil
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
