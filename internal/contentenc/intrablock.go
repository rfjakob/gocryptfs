package contentenc

// IntraBlock identifies a part of a file block
type IntraBlock struct {
	// BlockNo is the block number in the file
	BlockNo uint64
	// Skip is an offset into the block payload
	// In forward mode: block plaintext
	// In reverse mode: offset into block ciphertext. Takes the header into
	// account.
	Skip uint64
	// Length of payload data in this block
	// In forward mode: length of the plaintext
	// In reverse mode: length of the ciphertext. Takes header and trailer into
	// account.
	Length uint64
	fs     *ContentEnc
}

// IsPartial - is the block partial? This means we have to do read-modify-write.
func (ib *IntraBlock) IsPartial() bool {
	if ib.Skip > 0 || ib.Length < ib.fs.plainBS {
		return true
	}
	return false
}

// BlockCipherOff returns the ciphertext offset corresponding to BlockNo
func (ib *IntraBlock) BlockCipherOff() (offset uint64) {
	return ib.fs.BlockNoToCipherOff(ib.BlockNo)
}

// BlockPlainOff returns the plaintext offset corresponding to BlockNo
func (ib *IntraBlock) BlockPlainOff() (offset uint64) {
	return ib.fs.BlockNoToPlainOff(ib.BlockNo)
}

// CropBlock - crop a potentially larger plaintext block down to the relevant part
func (ib *IntraBlock) CropBlock(d []byte) []byte {
	lenHave := len(d)
	lenWant := int(ib.Skip + ib.Length)
	if lenHave < lenWant {
		return d[ib.Skip:lenHave]
	}
	return d[ib.Skip:lenWant]
}

// JointCiphertextRange is the ciphertext range corresponding to the sum of all
// "blocks" (complete blocks)
func (ib *IntraBlock) JointCiphertextRange(blocks []IntraBlock) (offset uint64, length uint64) {
	firstBlock := blocks[0]
	lastBlock := blocks[len(blocks)-1]

	offset = ib.fs.BlockNoToCipherOff(firstBlock.BlockNo)
	offsetLast := ib.fs.BlockNoToCipherOff(lastBlock.BlockNo)
	length = offsetLast + ib.fs.cipherBS - offset

	return offset, length
}

// JointPlaintextRange is the plaintext range corresponding to the sum of all
// "blocks" (complete blocks)
func JointPlaintextRange(blocks []IntraBlock) (offset uint64, length uint64) {
	firstBlock := blocks[0]
	lastBlock := blocks[len(blocks)-1]

	offset = firstBlock.BlockPlainOff()
	length = lastBlock.BlockPlainOff() + lastBlock.fs.PlainBS() - offset

	return offset, length
}
