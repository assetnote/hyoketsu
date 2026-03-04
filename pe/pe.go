package pe

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsNETAssembly checks if a PE file is a .NET assembly by looking for a
// non-zero CLR Runtime Header data directory entry.
func IsNETAssembly(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil {
		return false, fmt.Errorf("read PE header: %w", err)
	}
	buf = buf[:n]

	if n < 2 || buf[0] != 'M' || buf[1] != 'Z' {
		return false, nil
	}
	if n < 0x3C+4 {
		return false, nil
	}
	peOffset := int(binary.LittleEndian.Uint32(buf[0x3C:]))

	if peOffset+4 > n {
		return false, nil
	}
	if buf[peOffset] != 'P' || buf[peOffset+1] != 'E' || buf[peOffset+2] != 0 || buf[peOffset+3] != 0 {
		return false, nil
	}

	optHeaderOffset := peOffset + 4 + 20
	if optHeaderOffset+2 > n {
		return false, nil
	}
	magic := binary.LittleEndian.Uint16(buf[optHeaderOffset:])

	var dataDirOffset int
	switch magic {
	case 0x10b: // PE32
		dataDirOffset = optHeaderOffset + 96
	case 0x20b: // PE32+
		dataDirOffset = optHeaderOffset + 112
	default:
		return false, nil
	}

	clrEntryOffset := dataDirOffset + 14*8
	if clrEntryOffset+8 > n {
		return false, nil
	}

	rva := binary.LittleEndian.Uint32(buf[clrEntryOffset:])
	size := binary.LittleEndian.Uint32(buf[clrEntryOffset+4:])

	return rva != 0 && size != 0, nil
}

var microsoftTokens = map[string]bool{
	"b77a5c561934e089": true, // ECMA key (System.*, mscorlib)
	"b03f5f7f11d50a3a": true, // Microsoft extended libs
	"31bf3856ad364e35": true, // Microsoft.* libs
	"adb9793829ddae60": true, // .NET Core / modern Microsoft.*
	"cc7b13ffcd2ddd51": true, // .NET Standard / corefx
}

func IsMicrosoftToken(token string) bool {
	return microsoftTokens[strings.ToLower(token)]
}


type sectionHeader struct {
	virtualAddress uint32
	virtualSize    uint32
	rawDataOffset  uint32
	rawDataSize    uint32
}

func rvaToOffset(rva uint32, sections []sectionHeader) (int64, bool) {
	for _, s := range sections {
		if rva >= s.virtualAddress && rva < s.virtualAddress+s.virtualSize {
			return int64(s.rawDataOffset) + int64(rva-s.virtualAddress), true
		}
	}
	return 0, false
}

func readAt(r io.ReaderAt, offset int64, buf []byte) error {
	_, err := r.ReadAt(buf, offset)
	return err
}

// PublicKeyToken extracts the public key token from a .NET assembly.
// Returns empty string if the assembly has no public key.
func PublicKeyToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var hdr [512]byte
	if err := readAt(f, 0, hdr[:]); err != nil {
		return "", fmt.Errorf("read PE header: %w", err)
	}

	if hdr[0] != 'M' || hdr[1] != 'Z' {
		return "", fmt.Errorf("not a PE file")
	}

	peOffset := int(binary.LittleEndian.Uint32(hdr[0x3C:]))
	if peOffset+4 > len(hdr) {
		return "", fmt.Errorf("PE offset out of range")
	}
	if hdr[peOffset] != 'P' || hdr[peOffset+1] != 'E' || hdr[peOffset+2] != 0 || hdr[peOffset+3] != 0 {
		return "", fmt.Errorf("invalid PE signature")
	}

	coffOffset := peOffset + 4
	numSections := int(binary.LittleEndian.Uint16(hdr[coffOffset+2:]))
	optHeaderOffset := coffOffset + 20

	magic := binary.LittleEndian.Uint16(hdr[optHeaderOffset:])
	var dataDirOffset int
	switch magic {
	case 0x10b: // PE32
		dataDirOffset = optHeaderOffset + 96
	case 0x20b: // PE32+
		dataDirOffset = optHeaderOffset + 112
	default:
		return "", fmt.Errorf("unknown PE magic %#x", magic)
	}

	clrEntryOffset := dataDirOffset + 14*8
	if clrEntryOffset+8 > len(hdr) {
		return "", fmt.Errorf("CLR entry out of header range")
	}
	clrRVA := binary.LittleEndian.Uint32(hdr[clrEntryOffset:])
	if clrRVA == 0 {
		return "", fmt.Errorf("not a .NET assembly")
	}

	sectionTableOffset := optHeaderOffset + int(binary.LittleEndian.Uint16(hdr[coffOffset+16:]))
	sections := make([]sectionHeader, numSections)
	for i := 0; i < numSections; i++ {
		off := int64(sectionTableOffset + i*40)
		var sh [40]byte
		if err := readAt(f, off, sh[:]); err != nil {
			return "", fmt.Errorf("read section header: %w", err)
		}
		sections[i] = sectionHeader{
			virtualSize:    binary.LittleEndian.Uint32(sh[8:]),
			virtualAddress: binary.LittleEndian.Uint32(sh[12:]),
			rawDataSize:    binary.LittleEndian.Uint32(sh[16:]),
			rawDataOffset:  binary.LittleEndian.Uint32(sh[20:]),
		}
	}

	clrFileOffset, ok := rvaToOffset(clrRVA, sections)
	if !ok {
		return "", fmt.Errorf("cannot resolve CLR RVA")
	}
	var clrHdr [72]byte
	if err := readAt(f, clrFileOffset, clrHdr[:]); err != nil {
		return "", fmt.Errorf("read CLR header: %w", err)
	}
	metadataRVA := binary.LittleEndian.Uint32(clrHdr[8:])
	metadataSize := binary.LittleEndian.Uint32(clrHdr[12:])
	if metadataRVA == 0 || metadataSize == 0 {
		return "", fmt.Errorf("no metadata")
	}

	metadataOffset, ok := rvaToOffset(metadataRVA, sections)
	if !ok {
		return "", fmt.Errorf("cannot resolve metadata RVA")
	}
	if metadataSize > 4*1024*1024 {
		return "", fmt.Errorf("metadata too large")
	}
	metadata := make([]byte, metadataSize)
	if err := readAt(f, metadataOffset, metadata); err != nil {
		return "", fmt.Errorf("read metadata: %w", err)
	}

	if len(metadata) < 16 || string(metadata[0:4]) != "BSJB" {
		return "", fmt.Errorf("invalid metadata signature")
	}

	versionLen := int(binary.LittleEndian.Uint32(metadata[12:]))
	paddedVersionLen := (versionLen + 3) & ^3
	streamHeaderStart := 16 + paddedVersionLen

	if streamHeaderStart+4 > len(metadata) {
		return "", fmt.Errorf("metadata too short for stream headers")
	}

	numStreams := int(binary.LittleEndian.Uint16(metadata[streamHeaderStart+2:]))
	pos := streamHeaderStart + 4

	var tildeOffset, tildeSize int
	var blobOffset, blobSize int
	for i := 0; i < numStreams; i++ {
		if pos+8 > len(metadata) {
			break
		}
		sOffset := int(binary.LittleEndian.Uint32(metadata[pos:]))
		sSize := int(binary.LittleEndian.Uint32(metadata[pos+4:]))
		pos += 8
		nameStart := pos
		for pos < len(metadata) && metadata[pos] != 0 {
			pos++
		}
		name := string(metadata[nameStart:pos])
		pos++
		pos = (pos + 3) & ^3

		switch name {
		case "#~", "#-":
			tildeOffset = sOffset
			tildeSize = sSize
		case "#Blob":
			blobOffset = sOffset
			blobSize = sSize
		}
	}

	if tildeSize == 0 {
		return "", fmt.Errorf("#~ stream not found")
	}
	if blobSize == 0 {
		return "", fmt.Errorf("#Blob stream not found")
	}

	tilde := metadata[tildeOffset:]
	if len(tilde) < 24 {
		return "", fmt.Errorf("#~ stream too short")
	}

	heapSizes := tilde[6]
	blobIndexSize := 2
	if heapSizes&0x04 != 0 {
		blobIndexSize = 4
	}
	stringIndexSize := 2
	if heapSizes&0x01 != 0 {
		stringIndexSize = 4
	}
	guidIndexSize := 2
	if heapSizes&0x02 != 0 {
		guidIndexSize = 4
	}

	validTables := binary.LittleEndian.Uint64(tilde[8:])

	rowCountsStart := 24
	numValidTables := 0
	for i := 0; i < 64; i++ {
		if validTables&(1<<uint(i)) != 0 {
			numValidTables++
		}
	}
	if len(tilde) < rowCountsStart+numValidTables*4 {
		return "", fmt.Errorf("#~ stream too short for row counts")
	}

	rowCounts := make([]uint32, 64)
	idx := 0
	for i := 0; i < 64; i++ {
		if validTables&(1<<uint(i)) != 0 {
			rowCounts[i] = binary.LittleEndian.Uint32(tilde[rowCountsStart+idx*4:])
			idx++
		}
	}

	if validTables&(1<<0x20) == 0 || rowCounts[0x20] == 0 {
		return "", fmt.Errorf("no Assembly table")
	}

	tablesStart := rowCountsStart + numValidTables*4
	offset := tablesStart

	for tableIdx := 0; tableIdx < 0x20; tableIdx++ {
		if validTables&(1<<uint(tableIdx)) == 0 {
			continue
		}
		rowSize := tableRowSize(tableIdx, rowCounts, stringIndexSize, guidIndexSize, blobIndexSize)
		offset += int(rowCounts[tableIdx]) * rowSize
	}

	// Assembly row: HashAlgId(4) + Version(4×2) + Flags(4) + PublicKey(blob) + Name + Culture
	assemblyRowStart := offset
	publicKeyBlobIdx := assemblyRowStart + 4 + 2 + 2 + 2 + 2 + 4
	if publicKeyBlobIdx+blobIndexSize > len(tilde) {
		return "", fmt.Errorf("Assembly row out of range")
	}

	var blobIdx uint32
	if blobIndexSize == 2 {
		blobIdx = uint32(binary.LittleEndian.Uint16(tilde[publicKeyBlobIdx:]))
	} else {
		blobIdx = binary.LittleEndian.Uint32(tilde[publicKeyBlobIdx:])
	}

	if blobIdx == 0 {
		return "", nil
	}

	blob := metadata[blobOffset:]
	if int(blobIdx) >= len(blob) {
		return "", fmt.Errorf("blob index out of range")
	}
	blobData := blob[blobIdx:]
	blobLen, bytesRead := decodeCompressedUint(blobData)
	if bytesRead == 0 || int(blobLen) > len(blobData)-bytesRead {
		return "", fmt.Errorf("invalid blob length")
	}
	publicKey := blobData[bytesRead : bytesRead+int(blobLen)]
	if len(publicKey) == 0 {
		return "", nil
	}

	hash := sha1.Sum(publicKey)
	token := make([]byte, 8)
	for i := 0; i < 8; i++ {
		token[i] = hash[len(hash)-1-i]
	}
	return fmt.Sprintf("%x", token), nil
}

func decodeCompressedUint(data []byte) (value uint32, bytesRead int) {
	if len(data) == 0 {
		return 0, 0
	}
	b0 := data[0]
	if b0&0x80 == 0 {
		return uint32(b0), 1
	}
	if b0&0xC0 == 0x80 {
		if len(data) < 2 {
			return 0, 0
		}
		return uint32(b0&0x3F)<<8 | uint32(data[1]), 2
	}
	if b0&0xE0 == 0xC0 {
		if len(data) < 4 {
			return 0, 0
		}
		return uint32(b0&0x1F)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), 4
	}
	return 0, 0
}

func tableRowSize(tableIdx int, rowCounts []uint32, strSize, guidSize, blobSize int) int {
	codedIndexSize := func(tagBits int, tables []int) int {
		maxRows := uint32(0)
		for _, t := range tables {
			if t < len(rowCounts) && rowCounts[t] > maxRows {
				maxRows = rowCounts[t]
			}
		}
		if maxRows < (1 << (16 - tagBits)) {
			return 2
		}
		return 4
	}

	simpleIndexSize := func(table int) int {
		if table < len(rowCounts) && rowCounts[table] > 0xFFFF {
			return 4
		}
		return 2
	}

	switch tableIdx {
	case 0x00: // Module
		return 2 + strSize + guidSize + guidSize + guidSize
	case 0x01: // TypeRef
		resScope := codedIndexSize(2, []int{0x00, 0x01, 0x1A, 0x23, 0x26, 0x27})
		return resScope + strSize + strSize
	case 0x02: // TypeDef
		extends := codedIndexSize(2, []int{0x01, 0x02, 0x1B})
		fieldList := simpleIndexSize(0x04)
		methodList := simpleIndexSize(0x06)
		return 4 + strSize + strSize + extends + fieldList + methodList
	case 0x04: // Field
		return 2 + strSize + blobSize
	case 0x06: // MethodDef
		paramList := simpleIndexSize(0x08)
		return 4 + 2 + 2 + strSize + blobSize + paramList
	case 0x08: // Param
		return 2 + 2 + strSize
	case 0x09: // InterfaceImpl
		typeDefIdx := simpleIndexSize(0x02)
		iface := codedIndexSize(2, []int{0x01, 0x02, 0x1B})
		return typeDefIdx + iface
	case 0x0A: // MemberRef
		memberRefParent := codedIndexSize(3, []int{0x01, 0x02, 0x06, 0x1A, 0x1B})
		return memberRefParent + strSize + blobSize
	case 0x0B: // Constant
		hasConstant := codedIndexSize(2, []int{0x04, 0x08, 0x17})
		return 2 + hasConstant + blobSize
	case 0x0C: // CustomAttribute
		parent := codedIndexSize(5, []int{0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
			0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x2C})
		attrType := codedIndexSize(3, []int{0x02, 0x06, 0x0A})
		return parent + attrType + blobSize
	case 0x0D: // FieldMarshal
		hasFieldMarshal := codedIndexSize(1, []int{0x04, 0x08})
		return hasFieldMarshal + blobSize
	case 0x0E: // DeclSecurity
		hasDeclSecurity := codedIndexSize(2, []int{0x02, 0x06, 0x20})
		return 2 + hasDeclSecurity + blobSize
	case 0x0F: // ClassLayout
		return 2 + 4 + simpleIndexSize(0x02)
	case 0x10: // FieldLayout
		return 4 + simpleIndexSize(0x04)
	case 0x11: // StandAloneSig
		return blobSize
	case 0x12: // EventMap
		return simpleIndexSize(0x02) + simpleIndexSize(0x14)
	case 0x14: // Event
		eventType := codedIndexSize(2, []int{0x01, 0x02, 0x1B})
		return 2 + strSize + eventType
	case 0x15: // PropertyMap
		return simpleIndexSize(0x02) + simpleIndexSize(0x17)
	case 0x17: // Property
		return 2 + strSize + blobSize
	case 0x18: // MethodSemantics
		association := codedIndexSize(1, []int{0x14, 0x17})
		return 2 + simpleIndexSize(0x06) + association
	case 0x19: // MethodImpl
		methodDefOrRef := codedIndexSize(1, []int{0x06, 0x0A})
		return simpleIndexSize(0x02) + methodDefOrRef + methodDefOrRef
	case 0x1A: // ModuleRef
		return strSize
	case 0x1B: // TypeSpec
		return blobSize
	case 0x1C: // ImplMap
		memberForwarded := codedIndexSize(1, []int{0x04, 0x06})
		return 2 + memberForwarded + strSize + simpleIndexSize(0x1A)
	case 0x1D: // FieldRVA
		return 4 + simpleIndexSize(0x04)
	case 0x1E: // ENCLog (edit-and-continue, rare)
		return 4 + 4
	case 0x1F: // ENCMap (edit-and-continue, rare)
		return 4
	default:
		return 0
	}
}
