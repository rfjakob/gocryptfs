package contentenc

// intraBlock identifies a part of a file block
type intraBlock struct {
	BlockNo uint64 // Block number in file
	Skip    uint64 // Offset into block plaintext
	Length  uint64 // Length of data from this block
	fs      *ContentEnc
}

// isPartial - is the block partial? This means we have to do read-modify-write.
func (ib *intraBlock) IsPartial() bool {
	if ib.Skip > 0 || ib.Length < ib.fs.plainBS {
		return true
	}
	return false
}

// CiphertextRange - get byte range in ciphertext file corresponding to BlockNo
// (complete block)
func (ib *intraBlock) CiphertextRange() (offset uint64, length uint64) {
	return ib.fs.BlockNoToCipherOff(ib.BlockNo), ib.fs.cipherBS
}

// PlaintextRange - get byte range in plaintext corresponding to BlockNo
// (complete block)
func (ib *intraBlock) PlaintextRange() (offset uint64, length uint64) {
	return ib.fs.BlockNoToPlainOff(ib.BlockNo), ib.fs.plainBS
}

// CropBlock - crop a potentially larger plaintext block down to the relevant part
func (ib *intraBlock) CropBlock(d []byte) []byte {
	lenHave := len(d)
	lenWant := int(ib.Skip + ib.Length)
	if lenHave < lenWant {
		return d[ib.Skip:lenHave]
	}
	return d[ib.Skip:lenWant]
}

// Ciphertext range corresponding to the sum of all "blocks" (complete blocks)
func (ib *intraBlock) JointCiphertextRange(blocks []intraBlock) (offset uint64, length uint64) {
	firstBlock := blocks[0]
	lastBlock := blocks[len(blocks)-1]

	offset = ib.fs.BlockNoToCipherOff(firstBlock.BlockNo)
	offsetLast := ib.fs.BlockNoToCipherOff(lastBlock.BlockNo)
	length = offsetLast + ib.fs.cipherBS - offset

	return offset, length
}
