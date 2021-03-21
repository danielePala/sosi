/*
 Definition of the TPDUs used by ISO 8327 session protocol and associated
 validation functions.

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
	reasonCode   = 0x32 // Reason Code PI code
	keepTConn    = 0x00 // Transport connection is kept
	releaseTConn = 0x01 // Transport connection is released
	// DT-related defs
	dtID = 0x01 // ID of a DT SPDU
	// GT-related defs
	gtID = 0x01 // ID of a GT SPDU
	// PT-related defs
	ptID = 0x02 // ID of a PT SPDU
	// AB-related defs
	abID    = 0x19 // ID of an AB SPDU
	rpvCode = 0x31 // Reflect Parameter Values PI code
	// AA-related defs
	aaID = 0x1a // ID of an AA SPDU
	// CDO-related defs
	cdoID       = 0x0f  // ID of a CDO SPDU
	udMaxLenCdo = 65528 // CDO User Data max length
	// common defs for various SPDUs
	ciCode              = 0x01                // Connection Identifier PGI code
	calledURcode        = 0x09                // Called SS-user Reference PI code
	crCode              = 0x0b                // Common Reference PI code
	crMaxLen            = 64                  // Common Reference max length
	infoCode            = 0x0c                // Additional Reference Information PI code
	infoMaxLen          = 4                   // Additional Reference Information max length
	itemCode            = 0x05                // Connect/Accept Item PGI code
	poCode              = 0x13                // Protocol Options PI code
	poLen               = 1                   // Protocol Options length
	poNormalConc        = 0                   // don't use extended concatenated SPDUs
	poExtendedConc      = 1                   // ability to receive extended concatenated SPDUs
	tsizeCode           = 0x15                // TSDU Maximum Size PI code
	tsizeLen            = 4                   // TSDU Maximum Size length
	vnCode              = 0x16                // Version Number PI code
	vnLen               = 1                   // Version Number length
	vnOne               = 1                   // Version Number 1
	vnTwo               = 2                   // Version Number 2
	vnMax               = 3                   // Version Number max value
	tiCode              = 0x10                // Token Item PI code
	isnCode             = 0x17                // Initial Serial Number PI code
	tsiCode             = 0x1a                // Token Setting Item PI code
	tsiLen              = 1                   // Token Setting Item length
	sisnCode            = 0x37                // Second Initial Serial Number PI code
	ulsnCode            = 0x38                // Upper Limit Serial Number PI code
	lisnCode            = 0x39                // Large Initial Serial Number PI code
	lsisnCode           = 0x3a                // Large Second Initial Serial Number PI code
	surCode             = 0x14                // Session User Requirements PI code
	halfDuplex          = 1                   // half-duplex functional unit
	duplex              = 2                   // duplex functional unit
	surValue            = halfDuplex + duplex // half-duplex and duplex functional units
	surLen              = 2                   // Session User Requirements length
	surMax              = 8191                // Session User Requirements max value
	srcSSELCode         = 0x33                // Calling Session Selector PI code
	dstSSELCode         = 0x34                // Called Session Selector PI code
	sselMaxLen          = 16                  // Session Selector max length
	udCode              = 0xc1                // User Data PGI code
	udMaxLen            = 512                 // User Data max length
	udMaxExt            = 10240               // Extended User Data max length
	eiCode              = 0x19                // Enclosure Item PI code
	eiMax               = 2                   // Enclosure Item max value
	eiMiddle       byte = 0                   // Enclosure Item indicating middle of SSDU
	eiBegin        byte = 1                   // Enclosure Item indicating beginning of SSDU
	eiEnd          byte = 2                   // Enclosure Item indicating end of SSDU
	eiLen               = 1                   // Enclosure Item length
	smallUnit           = 254                 // Max size of a 'small' unit
	bigUnit             = 0xff                // Identifier of a 'big' unit
	smallLen            = 2                   // Header length of a 'small' unit
	bigLen              = 4                   // Header length of a 'big' unit
	urMaxLen            = 64                  // Calling or called SS-user Reference max length
	tdisCode            = 0x11                // Transport Disconnect PI code
)

// variables associated with a CN request
type cnVars struct {
	ConnID
	connAcc
	sesUserReq       [2]byte // list of the proposed functional units
	locSSEL, remSSEL []byte
	userData         []byte
	dataOverflow     bool
	ovfData          []byte // user data to be sent in one or more CONNECT DATA OVERFLOW SPDUs
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
	encItem    byte // Enclosure Item
	reasonCode []byte
}

// Connection Identifier PGI, which is supplied by the calling SS-user
// to enable the SS-users to identify this specific session connection.
type ConnID struct {
	SSUsrRef, ComRef, RefInfo []byte
}

// Connect/Accept Item PGI
type connAcc struct {
	// Proposes the initial token positions for each token available on this
	// connection, as derived from the functional units proposed in the Session
	// User Requirements parameter. The initial token positions can be
	// specified to be on the initiator’s side or on the acceptor’s side or the
	// initiator can specify that the decision is to be made by the server.
	tokenSetting byte
	// if present and not zero, indicates the initiator’s proposed values for
	// the maximum TSDU sizes for each direction of transfer. If this parameter
	// is not present or is zero, the TSDU size is not limited.
	maxTSDUSize [4]byte
	// these parameters are never proposed nor used by SOSI.
	initialSN, secondSN []byte
	// these parameters are never proposed nor used by SOSI.
	upperLimSN, largeSN, largeSecSN []byte
	// the Protocol Options parameter is never proposed nor used by SOSI.
	// The Version Number parameter identifies all versions of the protocol
	// which are supported and are suitable for the session connection.
	protOpt, version byte
}

type ReadInfo struct {
	Data        []byte
	StartOfTSDU bool // is this data the first part of a SSDU?
	EndOfTSDU   bool // is this data the last part of a SSDU?
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
	return unit(cnID, params)
}

/* OA - Overflow Accept */
func oa(MaxTSDUSize [4]byte, version byte) []byte {
	tsdu := unit(tsizeCode, MaxTSDUSize[:])
	vn := unit(vnCode, []byte{version})
	// build complete SPDU
	params := units(tsdu, vn)
	return unit(oaID, params)
}

/* AC - Accept */
func ac(cv acVars) []byte {
	ci := makeConnID(cv.ConnID, calledURcode) // Connection Identifier PGI
	item := makeConnAcc(cv.cnVars)            // Connect/Accept Item PGI
	ti := unit(tiCode, []byte{cv.tokenItem})  // Token Item PI
	// If both the half-duplex functional unit and the duplex functional
	// unit were indicated in the CONNECT SPDU, then the ACCEPT SPDU shall
	// propose which one is to be available.
	// Whenever possible we try to use duplex.
	var acSur [2]byte
	if (cv.sesUserReq[1] & duplex) == duplex {
		acSur[1] = duplex
	} else {
		acSur[1] = halfDuplex
	}
	sur := unit(surCode, acSur[:]) // Session User Requirements PI
	// The Enclosure Item parameter, if present, shall indicate that the
	// SPDU is the beginning, but not end of the SSDU. This parameter
	// shall not be present if Protocol Version 1 is selected.
	ei := []byte{}
	if cv.version == vnTwo {
		ei = unit(eiCode, []byte{cv.enclItem}) // Enclosure Item PI
	}
	srcSSel := unit(srcSSELCode, cv.locSSEL) // Calling Session Selector PI
	dstSSel := unit(dstSSELCode, cv.remSSEL) // Called Session Selector PI
	ud := unit(udCode, cv.userData)          // User Data PGI
	// build complete SPDU
	params := units(ci, item, ti, sur, ei, srcSSel, dstSSel, ud)
	return unit(acID, params)
}

/* RF - Refuse */
func rf(v rfVars) []byte {
	ci := makeConnID(v.ConnID, calledURcode) // Connection Identifier PGI
	td := unit(tdisCode, []byte{v.tdisc})    // Transport Disconnect PI
	sur := unit(surCode, v.sesUserReq[:])    // Session User Requirements PI
	vn := unit(vnCode, []byte{v.version})    // Session User Requirements PI
	ei := unit(eiCode, []byte{v.encItem})    // Enclosure Item PI
	rc := unit(reasonCode, v.reasonCode)     // Reason Code PI
	// build complete SPDU
	params := units(ci, td, sur, vn, ei, rc)
	return unit(rfID, params)
}

/* DT - Data Transfer */
// The DATA TRANSFER SPDU contains:
//   a) An Enclosure Item parameter to indicate the beginning and end of SSDU
//      when segmenting has been selected. When segmenting has been selected,
//      the Enclosure Item parameter is always present and indicates whether the
//      SPDU is the beginning, middle or end of the SSDU. When segmenting has not
//      been selected, the Enclosure Item parameter is not present.
//   b) A User Information Field to transfer transparent user data whose maximum
//      size is unlimited when segmenting has not been selected and whose maximum
//      size is limited by the maximum TSDU size when segmenting has been
//      selected.
func dt(segmenting bool, enclItem byte, userInfo []byte) []byte {
	var ei []byte
	if segmenting == true {
		ei = unit(eiCode, []byte{enclItem}) // Enclosure Item PI
	} else {
		ei = nil
	}
	// build complete SPDU
	return append(unit(dtID, ei), userInfo...)
}

/* GT - Give Tokens */
func gt(tokenItem, enclItem byte, userData []byte) []byte {
	ti := unit(tiCode, []byte{tokenItem}) // Token Item PI
	ei := unit(eiCode, []byte{enclItem})  // Enclosure Item PI
	ud := unit(udCode, userData)          // User Data PGI
	// build complete SPDU
	params := units(ti, ei, ud)
	return unit(gtID, params)
}

/* PT - Give Tokens */
func pt(tokenItem, enclItem byte, userData []byte) []byte {
	ti := unit(tiCode, []byte{tokenItem}) // Token Item PI
	ei := unit(eiCode, []byte{enclItem})  // Enclosure Item PI
	ud := unit(udCode, userData)          // User Data PGI
	// build complete SPDU
	params := units(ti, ei, ud)
	return unit(ptID, params)
}

/* AB - Abort */
func ab(tdis, enclItem byte, rParamVals, userData []byte) []byte {
	td := unit(tdisCode, []byte{tdis})   // Transport Disconnect PI
	ei := unit(eiCode, []byte{enclItem}) // Enclosure Item PI
	rpv := unit(rpvCode, rParamVals)     // Reflect Parameter Values PI
	ud := unit(udCode, userData)         // User Data PGI
	// build complete SPDU
	params := units(td, ei, rpv, ud)
	return unit(abID, params)
}

/* AB - Abort Accept */
func aa() []byte {
	return unit(aaID, nil)
}

/* CDO - Connect Data Overflow */
func cdo(enclItem byte, userData []byte) []byte {
	ei := unit(eiCode, []byte{enclItem}) // Enclosure Item PI
	ud := unit(udCode, userData)         // User Data PGI
	// build complete SPDU
	params := units(ei, ud)
	return unit(cdoID, params)
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
		buf := append([]byte{code}, byte(bigUnit))
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
		if pID == id {
			return param[:pLen+headerLen(param)]
		}
		if pLen < paramLen(b) {
			param = param[pLen+headerLen(param):]
		} else {
			param = param[headerLen(param) : pLen+headerLen(param)]
		}
	}
	return nil
}

func getParameterValue(b []byte, id byte) []byte {
	param := getParameter(b, id)
	if param != nil {
		return param[headerLen(param):]
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

// read the header length of an SPDU, PGI or PI
func headerLen(buf []byte) int {
	if int(buf[1]) <= smallUnit {
		return smallLen
	}
	return bigLen
}

// read the Length Indicator field of an SPDU, PGI or PI
func paramLen(buf []byte) int {
	if int(buf[1]) <= smallUnit {
		return int(buf[1])
	}
	var lenInd uint16
	lenBuf := bytes.NewBuffer(buf[2:4])
	binary.Read(lenBuf, binary.BigEndian, &lenInd)
	return int(lenInd)
}

// concatenate any number of PI units
func units(bufs ...[]byte) (result []byte) {
	for _, buf := range bufs {
		result = append(result, buf...)
	}
	return result
}

// determine if a packet is a CN
func isCN(incoming []byte) bool {
	return isType(incoming, cnID)
}

// determine if a packet is an AC
func isAC(incoming []byte) bool {
	return isType(incoming, acID)
}

// determine if a packet is an OA
func isOA(incoming []byte) bool {
	return isType(incoming, oaID)
}

// determine if a packet is a CDO
func isCDO(incoming []byte) bool {
	return isType(incoming, cdoID)
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
	cv.locSSEL = getParameterValue(spdu, srcSSELCode)
	if len(cv.locSSEL) > sselMaxLen {
		return false, cv
	}
	// Called Session Selector
	cv.remSSEL = getParameterValue(spdu, dstSSELCode)
	if !bytes.Equal(cv.remSSEL, locSSEL) {
		return false, cv
	}
	// User Data or Extended User Data
	// try to read User Data
	cv.userData = getParameterValue(spdu, udCode)
	if cv.userData == nil {
		// try to read Extended User Data
		cv.userData = getParameterValue(spdu, cnEUDCode)
	}
	// Data Overflow
	valid, cv.dataOverflow = validateOverflow(spdu, cv)
	if !valid {
		return false, cv
	}
	return true, cv
}

// validate an AC SPDU
func validateAC(spdu []byte, cv cnVars) (valid bool, av acVars) {
	if !isValid(spdu) {
		return false, av
	}
	valid, av.cnVars = validateCN(spdu, cv.locSSEL)
	if !valid {
		return false, av
	}
	return true, av
}

// validate an RF SPDU
// If an OVERFLOW ACCEPT SPDU has been sent previously on the session
// connection, then the vn parameter shall have the
// same value as was indicated in the OVERFLOW ACCEPT SPDU, zero otherwise.
func validateRF(spdu []byte, vn byte) (valid bool, rv rfVars) {
	if !isValid(spdu) {
		return false, rv
	}
	// connection identifier
	valid, rv.ConnID = validateConnID(spdu, calledURcode)
	if !valid {
		return false, rv
	}
	// transport disconnect
	tdisc := getParameterValue(spdu, tdisCode)
	if len(tdisc) > 0 {
		rv.tdisc = tdisc[0]
		if (tdisc[0] != keepTConn) && (tdisc[0] != releaseTConn) {
			return false, rv
		}
	}
	// session user requirements
	var reasonTwo bool
	rv.reasonCode = getParameterValue(spdu, reasonCode)
	if len(rv.reasonCode) != 0 {
		reasonTwo = (rv.reasonCode[0] == 2)
	}
	valid, rv.sesUserReq = validateSUR(spdu)
	if (rv.sesUserReq[0] > 0 && (!reasonTwo)) || !valid {
		return false, rv
	}
	// version number
	versionNumber := getParameterValue(spdu, vnCode)
	if len(versionNumber) > 0 {
		rv.version = versionNumber[0]
		if len(versionNumber) != vnLen {
			return false, rv
		}
		if versionNumber[0] > vnMax {
			return false, rv
		}
		if (vn > 0) && (versionNumber[0] != vn) {
			return false, rv
		}
	} else {
		if vn > 0 {
			return false, rv
		}
		rv.version = vnOne // default value
	}
	// enclosure item
	encItem := getParameterValue(spdu, eiCode)
	if len(encItem) > 0 {
		rv.encItem = encItem[0]
		if encItem[0] > eiMax {
			return false, rv
		}
		if rv.version == vnOne {
			return false, rv
		}
	}
	// reason code
	if len(rv.reasonCode) > 0 {
		if (rv.reasonCode[0] > 2) && (rv.reasonCode[0] < 129) {
			return false, rv
		}
		if rv.reasonCode[0] > 134 {
			return false, rv
		}
		if (rv.version == vnOne) && (len(rv.reasonCode) > 513) {
			return false, rv
		}
		if (rv.version > vnOne) && (len(spdu) > 65539) {
			return false, rv
		}
	}
	return true, rv
}

func validateOA(spdu []byte, cv cnVars) (valid bool) {
	if !isValid(spdu) {
		return false
	}
	return true
}

func validateCDO(spdu []byte) (valid, last bool, data []byte) {
	if !isValid(spdu) {
		return false, false, nil
	}
	encItem := getParameterValue(spdu, eiCode)
	if len(encItem) != eiLen {
		return false, false, nil
	}
	if encItem[0] == eiEnd {
		last = true
	} else {
		if encItem[0] == eiMiddle {
			last = false
		} else {
			return false, false, nil
		}
	}
	data = getParameterValue(spdu, udCode)
	// The User Data field shall be present if the Enclosure Item has bit 2 = 0
	if last == false && data == nil {
		return false, false, nil
	}
	return true, last, data
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
	cid.SSUsrRef = getParameterValue(cidItem, urCode)
	cid.ComRef = getParameterValue(cidItem, crCode)
	cid.RefInfo = getParameterValue(cidItem, infoCode)
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

// validate a Connect/Accept Item PGI
func validateConnAcc(spdu []byte, sesUserReq [2]byte) (ok bool, ca connAcc) {
	caItem := getParameter(spdu, itemCode)
	if caItem == nil {
		return true, ca
	}
	if !isValid(caItem) {
		return false, ca
	}
	// Protocol Options
	po := getParameterValue(caItem, poCode)
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
	tsize := getParameterValue(caItem, tsizeCode)
	if tsize != nil {
		if len(tsize) != tsizeLen {
			return false, ca
		}
		copy(ca.maxTSDUSize[:], tsize)
	}
	// Version Number
	vn := getParameterValue(caItem, vnCode)
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
	}
	ca.initialSN = getParameterValue(caItem, isnCode)
	tsi := getParameterValue(caItem, tsiCode)
	if tsi != nil {
		if len(tsi) != tsiLen {
			return false, ca
		}
		ca.tokenSetting = tsi[0]
	}
	ca.secondSN = getParameterValue(caItem, sisnCode)
	ca.upperLimSN = getParameterValue(caItem, ulsnCode)
	ca.largeSN = getParameterValue(caItem, lisnCode)
	ca.largeSecSN = getParameterValue(caItem, lsisnCode)
	return true, ca
}

// validate a Session User Requirements PI
func validateSUR(spdu []byte) (ok bool, sur [2]byte) {
	sesUserReq := getParameterValue(spdu, surCode)
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

// The Data Overflow parameter shall be present if and only if there is more
// than 10240 octets of SS-user data and indicates to the responder that there
// is more SS-user data to follow. The first 10 240 octets of SS-user data are
// sent in the Extended User Data parameter. This parameter shall not be
// present if Protocol Version 1 is proposed.
func validateOverflow(spdu []byte, cn cnVars) (ok, overflow bool) {
	ca := cn.connAcc
	dataOverflow := getParameterValue(spdu, cnDOCode)
	if dataOverflow == nil {
		return true, false
	}
	if dataOverflow[0] == 0 {
		overflow = false
	} else {
		overflow = true
	}
	if len(cn.userData) < udMaxExt {
		return false, overflow
	}
	if len(dataOverflow) > cnDOLen {
		return false, overflow
	}
	if overflow == true && ca.version < vnTwo {
		return false, overflow
	}
	return true, overflow
}

func getData(tsdu []byte) (dt []byte) {
	if isGT(tsdu) {
		valid := validateGT(tsdu)
		if !valid {
			return nil
		}
		gtLen := headerLen(tsdu) + paramLen(tsdu)
		if len(tsdu) < gtLen {
			return nil
		}
		dt = tsdu[gtLen:]
	}
	if isDT(dt) {
		valid := validateDT(dt)
		if !valid {
			return nil
		}
		enclItem := getParameter(dt, eiCode)
		if len(enclItem) > 0 {
			return dt[5:]
		}
		return dt[2:]
	}
	return nil
}

func validateGT(spdu []byte) bool {
	if !isValid(spdu) {
		return false
	}
	return true
}

func validatePT(spdu []byte) bool {
	if !isValid(spdu) {
		return false
	}
	return true
}

func validateDT(spdu []byte) bool {
	if !isValid(spdu) {
		return false
	}
	// enclosure item
	encItem := getParameter(spdu, eiCode)
	encItem = encItem[headerLen(encItem):]
	if len(encItem) > 0 {
		if encItem[0] > eiMax {
			return false
		}
	}
	return true
}

func createSessionConn(cv cnVars, av acVars) (sconn *SOSIConn) {
	var ret SOSIConn
	// check if we are duplex of half-duplex
	if av.sesUserReq[1] == duplex {
		ret.Duplex = true
	} else {
		ret.Duplex = false
	}
	return &ret
}
