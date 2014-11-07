package sosi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	// SPDU-related defs
	unitMinLen = 2 // min length of an SPDU, PGI or PI unit
	// CN-related defs
	cnID          = 0x0d // ID of a CN SPDU
	callingURCode = 0x0a // Calling SS-user Reference PI code
	cnDOCode      = 0x3c // Data Overflow PI code
	cnDOLen       = 1
	cnEUDCode     = 0xc2 // Extended User Data PGI code
	// AC-related defs
	acID = 0x0e // ID of an AC SPDU
	// OA-related defs
	oaID = 0x10 // ID of an OA SPDU
	// RF-related defs
	rfID         = 0x0c // ID of an RF SPDU
	tdisCode     = 0x11 // Transport Disconnect PI code
	reasonCode   = 0x32 // Reason Code PI code
	keepTConn    = 0x00 // Transport connection is kept
	releaseTConn = 0x01 // Transport connection is released
	// DT-related defs
	dtID = 0x01 // ID of a DT SPDU
	// GT-related defs
	gtID = 0x01 // ID of a GT SPDU
	// PT-related defs
	ptID = 0x02 // ID of a PT SPDU
	// common defs for various SPDUs
	ciCode         = 0x01  // Connection Identifier PGI code
	calledURcode   = 0x09  // Called SS-user Reference PI code
	crCode         = 0x0b  // Common Reference PI code
	crMaxLen       = 64    // Common Reference max length
	infoCode       = 0x0c  // Additional Reference Information PI code
	infoMaxLen     = 4     // Additional Reference Information max length
	itemCode       = 0x05  // Connect/Accept Item PGI code
	poCode         = 0x13  // Protocol Options PI code
	poLen          = 1     // Protocol Options length
	poNormalConc   = 0     // don't use extended concatenated SPDUs
	poExtendedConc = 1     // ability to receive extended concatenated SPDUs
	tsizeCode      = 0x15  // TSDU Maximum Size PI code
	tsizeLen       = 4     // TSDU Maximum Size length
	vnCode         = 0x16  // Version Number PI code
	vnLen          = 1     // Version Number length
	vnOne          = 1     // Version Number 1
	vnTwo          = 2     // Version Number 2
	vnMax          = 3     // Version Number max value
	tiCode         = 0x10  // Token Item PI code
	isnCode        = 0x17  // Initial Serial Number PI code
	tsiCode        = 0x1a  // Token Setting Item PI code
	sisnCode       = 0x37  // Second Initial Serial Number PI code
	ulsnCode       = 0x38  // Upper Limit Serial Number PI code
	lisnCode       = 0x39  // Large Initial Serial Number PI code
	lsisnCode      = 0x3a  // Large Second Initial Serial Number PI code
	surCode        = 0x14  // Session User Requirements PI code
	surValue       = 3     // half-duplex and duplex functional units
	surLen         = 2     // Session User Requirements length
	surMax         = 8191  // Session User Requirements max value
	srcSSELCode    = 0x33  // Calling Session Selector PI code
	dstSSELCode    = 0x34  // Called Session Selector PI code
	sselMaxLen     = 16    // Session Selector max length
	udCode         = 0xc1  // User Data PGI code
	udMaxLen       = 512   // User Data max length
	udMaxExt       = 10240 // Extended User Data max length
	eiCode         = 0x19  // Enclosure Item PI code
	eiMax          = 3     // Enclosure Item max value
	smallUnit      = 254   // Max size of a 'small' unit
	bigUnit        = 0xff  // Identifier of a 'big' unit
	smallLen       = 2     // Header length of a 'small' unit
	bigLen         = 4     // Header length of a 'big' unit
	urMaxLen       = 64    // Calling or called SS-user Reference max length
)

// variables associated with a CN request
type cnVars struct {
	ConnID
	connAcc
	sesUserReq       [2]byte
	locSSEL, remSSEL []byte
	userData         []byte
	dataOverflow     bool
}

// variables associated with an AC response
type acVars struct {
	cnVars
	tokenItem byte // Token Item
	enclItem  byte // Enclosure Item
}

// variables associated with an RF response
type rfVars struct {
	ConnID
	tdisc      byte
	sesUserReq [2]byte
	version    byte
	enclItem   byte // Enclosure Item
	reasonCode []byte
}

// Connection Identifier PGI, which is supplied by the calling SS-user
// to enable the SS-users to identify this specific session connection.
type ConnID struct {
	SSUsrRef, ComRef, RefInfo []byte
}

// Connect/Accept Item PGI
type connAcc struct {
	tokenSetting                    byte
	maxTSDUSize                     [4]byte
	initialSN, secondSN             []byte
	upperLimSN, largeSN, largeSecSN []byte
	protOpt, version                byte
}

/* CN - Connect */
func cn(cv cnVars) []byte {
	ci := makeConnID(cv.ConnID, callingURCode) // Connection Identifier PGI
	item := makeConnAcc(cv)                    // Connect/Accept Item PGI
	sur := unit(surCode, cv.sesUserReq[:])     // Session User Requirements PI
	srcSSEL := unit(srcSSELCode, cv.locSSEL)   // Calling Session Selector PI
	dstSSEL := unit(dstSSELCode, cv.remSSEL)   // Called Session Selector PI
	var overflow []byte
	if cv.dataOverflow {
		overflow = []byte{0x01}
	}
	do := unit(cnDOCode, overflow) // Data Overflow PI
	var ud []byte
	if len(cv.userData) <= udMaxLen {
		// User Data PGI
		ud = unit(udCode, cv.userData)
	} else {
		// Extended User Data PGI
		if len(cv.userData) > udMaxExt {
			ud = unit(cnEUDCode, cv.userData[:udMaxExt])
		} else {
			ud = unit(cnEUDCode, cv.userData)
		}
	}
	// build complete SPDU
	params := units(ci, item, sur, srcSSEL, dstSSEL, do, ud)
	return spdu(params, cnID)
}

/* OA - Overflow Accept */
func oa(MaxTSDUSize [4]byte, version byte) []byte {
	tsdu := unit(tsizeCode, MaxTSDUSize[:])
	vn := unit(vnCode, []byte{version})
	// build complete SPDU
	params := units(tsdu, vn)
	return spdu(params, oaID)
}

/* AC - Accept */
func ac(cv acVars) []byte {
	ci := makeConnID(cv.ConnID, calledURcode) // Connection Identifier PGI
	item := makeConnAcc(cv.cnVars)            // Connect/Accept Item PGI
	ti := unit(tiCode, []byte{cv.tokenItem})  // Token Item PI
	sur := unit(surCode, cv.sesUserReq[:])    // Session User Requirements PI
	ei := unit(eiCode, []byte{cv.enclItem})   // Enclosure Item PI
	srcSSel := unit(srcSSELCode, cv.locSSEL)  // Calling Session Selector PI
	dstSSel := unit(dstSSELCode, cv.remSSEL)  // Called Session Selector PI
	ud := unit(udCode, cv.userData)           // User Data PGI
	// build complete SPDU
	params := units(ci, item, ti, sur, ei, srcSSel, dstSSel, ud)
	return spdu(params, acID)
}

/* RF - Refuse */
func rf(v rfVars) []byte {
	ci := makeConnID(v.ConnID, calledURcode) // Connection Identifier PGI
	td := unit(tdisCode, []byte{v.tdisc})    // Transport Disconnect PI
	sur := unit(surCode, v.sesUserReq[:])    // Session User Requirements PI
	vn := unit(vnCode, []byte{v.version})    // Session User Requirements PI
	ei := unit(eiCode, []byte{v.enclItem})   // Enclosure Item PI
	rc := unit(reasonCode, v.reasonCode)     // Reason Code PI
	// build complete SPDU
	params := units(ci, td, sur, vn, ei, rc)
	return spdu(params, rfID)
}

/* DT - Data Transfer */
func dt(enclItem byte, userInfo []byte) []byte {
	ei := unit(eiCode, []byte{enclItem}) // Enclosure Item PI
	// build complete SPDU
	return append(spdu(ei, dtID), userInfo...)
}

/* GT - Give Tokens */
func gt(tokenItem, enclItem byte, userData []byte) []byte {
	ti := unit(tiCode, []byte{tokenItem}) // Token Item PI
	ei := unit(eiCode, []byte{enclItem})  // Enclosure Item PI
	ud := unit(udCode, userData)          // User Data PGI
	// build complete SPDU
	params := units(ti, ei, ud)
	return spdu(params, gtID)
}

/* PT - Give Tokens */
func pt(tokenItem, enclItem byte, userData []byte) []byte {
	ti := unit(tiCode, []byte{tokenItem}) // Token Item PI
	ei := unit(eiCode, []byte{enclItem})  // Enclosure Item PI
	ud := unit(udCode, userData)          // User Data PGI
	// build complete SPDU
	params := units(ti, ei, ud)
	return spdu(params, ptID)
}

// construct a Connection Identifier PGI
func makeConnID(id ConnID, URcode byte) []byte {
	ur := unit(URcode, id.SSUsrRef)
	cr := unit(crCode, id.ComRef)
	info := unit(infoCode, id.RefInfo)
	piSet := units(ur, cr, info)
	return unit(ciCode, piSet)
}

// construct a Connect/Accept Item PGI
func makeConnAcc(cv cnVars) []byte {
	po := unit(poCode, []byte{cv.protOpt})
	zero := make([]byte, 4)
	var tsdu []byte
	if !bytes.Equal(cv.maxTSDUSize[:], zero) {
		tsdu = unit(tsizeCode, cv.maxTSDUSize[:])
	}
	vn := unit(vnCode, []byte{cv.version})
	isn := unit(isnCode, cv.initialSN)
	tsi := unit(tsiCode, []byte{cv.tokenSetting})
	sisn := unit(sisnCode, cv.secondSN)
	ulsn := unit(ulsnCode, cv.upperLimSN)
	lisn := unit(lisnCode, cv.largeSN)
	lsisn := unit(lsisnCode, cv.largeSecSN)
	piSet := units(po, tsdu, vn, isn, tsi, sisn, ulsn, lisn, lsisn)
	return unit(itemCode, piSet)
}

// create a PI or PGI unit
func unit(code byte, value []byte) []byte {
	if value == nil {
		return nil
	}
	size := len(value)
	if size < smallUnit {
		buf := append([]byte{code}, byte(size))
		return append(buf, value...)
	} else {
		buf := append([]byte{code}, bigUnit)
		sizeBuf := new(bytes.Buffer)
		binary.Write(sizeBuf, binary.BigEndian, int16(size))
		buf = append(buf, sizeBuf.Bytes()...)
		return append(buf, value...)
	}
}

// extract the parameter with the given ID from an SPDU or a PGI unit
// if b is an SPDU, PI units contained inside PGI units are _not_ evaluated.
// To evaluate them, the function must be called with the PGI as input.
func getParameter(b []byte, id byte) []byte {
	param := b[:]
	for len(param) > unitMinLen {
		pLen := paramLen(param)
		pID := param[0]
		param = param[headerLen(param):]
		if pID == id {
			return param[:pLen]
		}
		if pLen < paramLen(b) {
			param = param[pLen:]
		} else {
			param = param[:pLen]
		}
	}
	return nil
}

// determine if b represents a valid SPDU or PGI.
// if b is an SPDU, PI units contained inside PGI units are _not_ validated.
// To validate them, the function must be called with the PGI as input.
func isValid(b []byte) bool {
	if len(b) < unitMinLen {
		return false
	}
	param := b[:]
	for len(param) > 0 {
		if len(param) < unitMinLen {
			return false
		}
		hLen := headerLen(param)
		if len(param) < hLen {
			return false
		}
		pLen := paramLen(param)
		param = param[hLen:]
		if len(param) < pLen {
			return false
		}
		if pLen < paramLen(b) {
			param = param[pLen:]
		} else {
			param = param[:pLen]
		}
	}
	return true
}

// concatenate any number of PI units
func units(bufs ...[]byte) (result []byte) {
	for _, buf := range bufs {
		result = append(result, buf...)
	}
	return result
}

// build a complete SPDU
func spdu(params []byte, SI byte) []byte {
	LI := byte(len(params))
	buf := append([]byte{LI}, params...)
	return append([]byte{SI}, buf...)
}

// determine if a packet is a CN
func isCN(incoming []byte) bool {
	return isType(incoming, cnID)
}

// determine if a packet is an AC
func isAC(incoming []byte) bool {
	return isType(incoming, acID)
}

// determine if a packet is an RF
func isRF(incoming []byte) bool {
	return isType(incoming, rfID)
}

// determine if a packet is a GT
func isGT(incoming []byte) bool {
	return isType(incoming, gtID)
}

// determine if a packet is a DT
func isDT(incoming []byte) bool {
	return isType(incoming, dtID)
}

// determine if a packet is of type identified by id
// NOTE: the packet is not validated
func isType(incoming []byte, id byte) bool {
	if len(incoming) < unitMinLen {
		return false
	}
	return incoming[0] == id
}

// read the Length Indicator field of an SPDU, PGI or PI
func paramLen(buf []byte) int {
	if int(buf[1]) <= smallUnit {
		return int(buf[1])
	}
	var lenInd uint16
	lenBuf := bytes.NewBuffer(buf[2:3])
	binary.Read(lenBuf, binary.BigEndian, &lenInd)
	return int(lenInd)
}

// read the header length of an SPDU, PGI or PI
func headerLen(buf []byte) int {
	if int(buf[1]) <= smallUnit {
		return smallLen
	}
	return bigLen
}

// validate a CN SPDU
func validateCN(spdu []byte, locSSEL []byte) (valid bool, cv cnVars) {
	if !isValid(spdu) {
		return false, cv
	}
	// Connection Identifier
	valid, cv.ConnID = validateConnID(spdu, calledURcode)
	if !valid {
		return false, cv
	}
	// Connect/Accept Item
	valid, cv.connAcc = validateConnAcc(spdu, cv.sesUserReq)
	if !valid {
		return false, cv
	}
	// Session User Requirements
	valid, cv.sesUserReq = validateSUR(spdu)
	if !valid {
		return false, cv
	}
	// Calling Session Selector
	cv.locSSEL = getParameter(spdu, srcSSELCode)
	if len(cv.locSSEL) > sselMaxLen {
		return false, cv
	}
	// Called Session Selector
	cv.remSSEL = getParameter(spdu, dstSSELCode)
	if !bytes.Equal(cv.remSSEL, locSSEL) {
		return false, cv
	}
	// Data Overflow
	valid, cv.dataOverflow = validateOverflow(spdu, cv.connAcc)
	return true, cv
}

// validate an AC SPDU
func validateAC(spdu []byte, cv cnVars) (valid bool) {
	if !isValid(spdu) {
		return false
	}
	return true
}

// validate an RF SPDU
// If an OVERFLOW ACCEPT SPDU has been sent previously on the session
// connection, then the vn parameter shall have the
// same value as was indicated in the OVERFLOW ACCEPT SPDU, zero otherwise.
func validateRF(spdu []byte, vn byte) bool {
	if !isValid(spdu) {
		return false
	}
	// connection identifier
	ok, _ := validateConnID(spdu, calledURcode)
	if !ok {
		return false
	}
	// transport disconnect
	tdisc := getParameter(spdu, tdisCode)
	if len(tdisc) > 0 {
		if (tdisc[0] != keepTConn) && (tdisc[0] != releaseTConn) {
			return false
		}
	}
	// session user requirements
	var reasonTwo bool
	reason := getParameter(spdu, reasonCode)
	if len(reason) != 0 {
		reasonTwo = (reason[0] == 2)
	}
	ok, sur := validateSUR(spdu)
	if (sur[0] > 0 && (!reasonTwo)) || !ok {
		return false
	}
	// version number
	versionNumber := getParameter(spdu, vnCode)
	if len(versionNumber) > 0 {
		if len(versionNumber) != vnLen {
			return false
		}
		if versionNumber[0] > vnMax {
			return false
		}
		if (vn > 0) && (versionNumber[0] != vn) {
			return false
		}
	} else {
		if vn > 0 {
			return false
		}
		versionNumber = []byte{vnOne} // default value
	}
	// enclosure item
	encItem := getParameter(spdu, eiCode)
	if len(encItem) > 0 {
		if encItem[0] > eiMax {
			return false
		}
		if versionNumber[0] == vnOne {
			return false
		}
	}
	// reason code
	if len(reason) > 0 {
		if (reason[0] > 2) && (reason[0] < 129) {
			return false
		}
		if reason[0] > 134 {
			return false
		}
		if (versionNumber[0] == vnOne) && (len(reason) > 513) {
			return false
		}
		if (versionNumber[0] > vnOne) && (len(spdu) > 65539) {
			return false
		}
	}
	return true
}

// validate a Connection Identifier PGI
func validateConnID(spdu []byte, urCode byte) (ok bool, cid ConnID) {
	cidItem := getParameter(spdu, ciCode)
	if cidItem == nil {
		return true, cid
	}
	if !isValid(cidItem) {
		return false, cid
	}
	cid.SSUsrRef = getParameter(cidItem, urCode)
	cid.ComRef = getParameter(cidItem, crCode)
	cid.RefInfo = getParameter(cidItem, infoCode)
	if len(cid.SSUsrRef) > urMaxLen {
		return false, cid
	}
	if len(cid.ComRef) > crMaxLen {
		return false, cid
	}
	if len(cid.RefInfo) > infoMaxLen {
		return false, cid
	}
	return true, cid
}

// Connect/Accept Item PGI
/*type connAcc struct {
	tokenSetting                    byte
	maxTSDUSize                     [4]byte
	initialSN, secondSN             []byte
	upperLimSN, largeSN, largeSecSN []byte
	protOpt, version                byte
}*/

// validate a Connect/Accept Item PGI
func validateConnAcc(spdu []byte, sesUserReq [2]byte) (ok bool, ca connAcc) {
	caItem := getParameter(spdu, itemCode)
	if caItem == nil {
		return true, ca
	}
	/*if !isValid(caItem) {
		return false, ca
	}
	// Protocol Options
	po := getParameter(caItem, poCode)
	if po == nil {
		return false, ca
	} else {
		if len(po) != poLen {
			return false, ca
		}
		ca.protOpt = po[0]
		if (po[0] != poNormalConc) && (po[0] != poExtendedConc) {
			return false, ca
		}
	}
	// TSDU Maximum Size
	tsize := getParameter(caItem, tsizeCode)
	if tsize != nil {
		if len(tsize) != tsizeLen {
			return false, ca
		}
		copy(ca.maxTSDUSize[:], tsize)
	}
	// Version Number
	vn := getParameter(caItem, vnCode)
	if vn == nil {
		return false, ca
	} else {
		if len(vn) != vnLen {
			return false, ca
		}
		ca.version = vn[0]
		if vn[0] > vnMax {
			return false, ca
		}
	}*/
	/*isn := getParameter(caItem, isnCode)
	tsi := getParameter(caItem, tsiCode)
	sisn := getParameter(caItem, sisnCode)
	ulsn := getParameter(caItem, ulsnCode)
	lisn := getParameter(caItem, lisnCode)
	lsisn := getParameter(caItem, lsisnCode)*/
	return true, ca
}

// validate a Session User Requirements PI
func validateSUR(spdu []byte) (ok bool, sur [2]byte) {
	sesUserReq := getParameter(spdu, surCode)
	if len(sesUserReq) > 0 {
		if len(sesUserReq) != surLen {
			return false, sur
		}
		var surVal uint16
		buf := bytes.NewBuffer(sesUserReq)
		binary.Read(buf, binary.BigEndian, &surVal)
		if (surVal > surMax) || ((surVal & surValue) == 0) {
			return false, sur
		}
		copy(sur[:], sesUserReq)
	}
	return true, sur
}

func validateOverflow(spdu []byte, ca connAcc) (ok, overflow bool) {
	/*dataOverflow := getParameter(spdu, cnDOcode)
	if (len(dataOverflow) > cnDOLen) || ((dataOverflow == cnDOLen) && (cv.connAcc.version < vnTwo)) {
		return false, cv
	}*/
	return true, true
}

// decode an AC SPDU
// spdu is assumed to be _structurally_ valid (validateAC returned with success)
func decodeAC(spdu []byte) (v acVars) {
	return
}

// decode an RF SPDU
// the input is assumed to be valid (validateRF already called and passed)
func decodeRF(spdu []byte) (v rfVars) {
	v.SSUsrRef = getParameter(spdu, calledURcode)
	v.ComRef = getParameter(spdu, crCode)
	v.RefInfo = getParameter(spdu, infoCode)
	tdisc := getParameter(spdu, tdisCode)
	if len(tdisc) > 0 {
		v.tdisc = tdisc[0]
	} else {
		v.tdisc = 1
	}
	copy(v.sesUserReq[:], getParameter(spdu, surCode))
	version := getParameter(spdu, vnCode)
	if len(version) > 0 {
		v.version = version[0]
	}
	enclItem := getParameter(spdu, eiCode)
	if len(enclItem) > 0 {
		v.enclItem = enclItem[0]
	}
	v.reasonCode = getParameter(spdu, reasonCode)
	return v
}

func getDT(tsdu []byte) (dt []byte) {
	if isGT(tsdu) {
		gtLen := paramLen(tsdu)
		dt = tsdu[gtLen+2:]
	}
	if isDT(dt) {
		enclItem := getParameter(dt, eiCode)
		if len(enclItem) > 0 {
			return dt[5:]
		}
		return dt[2:]
	}
	return nil
}
