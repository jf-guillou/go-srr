package srr

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// SRR archive block types enum
const (
	BlockTypeSRRHeader  = 0x69
	BlockTypeFile       = 0x6A
	BlockTypeOsoHash    = 0x6B
	BlockTypePadding    = 0x6C
	BlockTypeRarFile    = 0x71
	BlockTypeRarStart   = 0x72
	BlockTypeRarVolume  = 0x73
	BlockTypePackedFile = 0x74
	BlockTypeSub        = 0x7A
	BlockTypeRarEnd     = 0x7B
)

// New bufferize file, and check for known header existence
func New(f *os.File) (*SRR, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size < 20 {
		return nil, errors.New("File is too small, minimum archive size is 20 bytes")
	}

	srr := &SRR{
		Reader:   bufio.NewReader(f),
		Filesize: size,
	}

	// Peek at first block
	header, err := srr.ReadBlockHeader()
	if header.BlockType() != BlockTypeSRRHeader {
		return nil, errors.New("File is not a valid SRR archive")
	}

	// Reset reader
	f.Seek(0, io.SeekStart)
	srr.Reader.Reset(f)

	return srr, nil
}

// SRR file struct
type SRR struct {
	Reader   *bufio.Reader
	Filesize int64
	Blocks   []Block
}

func (r *SRR) String() string {
	return fmt.Sprintf("SRR file - Size [%d]", r.Filesize)
}

// ReadBlock reads an entire block (header + payload)
func (r *SRR) ReadBlock() (Block, error) {
	header, err := r.ReadBlockHeader()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	blk, err := r.ReadBlockPayload(header)
	if err != nil {
		return nil, err
	}

	return blk, nil
}

// ReadBlockHeader reads block header
func (r *SRR) ReadBlockHeader() (BlockHeader, error) {
	var crc uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &crc); err != nil {
		return nil, err
	}
	var blockType byte
	if err := binary.Read(r.Reader, binary.LittleEndian, &blockType); err != nil {
		return nil, err
	}
	var flags uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}
	var payloadLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &payloadLength); err != nil {
		return nil, err
	}

	header := &BaseBlockHeader{
		CRC:           crc,
		blockType:     blockType,
		Flags:         flags,
		payloadLength: payloadLength,
	}

	if flags&0x8000 == 0 {
		return header, nil
	}

	var addLength uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &addLength); err != nil {
		return nil, err
	}

	return &LargeBlockHeader{
		BaseBlockHeader: header,
		addLength:       addLength,
	}, nil
}

// ReadBlockPayload reads payload content according to header block type
func (r *SRR) ReadBlockPayload(header BlockHeader) (Block, error) {
	switch header.BlockType() {
	case BlockTypeSRRHeader:
		return r.ReadHeaderBlock(header)
	case BlockTypeFile:
		return r.ReadFileBlock(header)
	case BlockTypeRarFile:
		return r.ReadRawBlock(header)
	default:
		return r.ReadRawBlock(header)
	}
}

// ReadHeaderBlock reads BlockTypeSRRHeader payload
func (r *SRR) ReadHeaderBlock(header BlockHeader) (*HeaderBlock, error) {
	var appNameSize uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &appNameSize); err != nil {
		return nil, err
	}

	appName := make([]byte, appNameSize)
	if err := binary.Read(r.Reader, binary.LittleEndian, appName); err != nil {
		return nil, err
	}

	return &HeaderBlock{
		BlockHeader: header,
		AppName:     string(appName),
	}, nil
}

// ReadFileBlock reads BlockTypeFile payload
func (r *SRR) ReadFileBlock(header BlockHeader) (*FileBlock, error) {
	var filenameLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &filenameLength); err != nil {
		return nil, err
	}

	filename := make([]byte, filenameLength)
	if err := binary.Read(r.Reader, binary.LittleEndian, filename); err != nil {
		return nil, err
	}

	payload := make([]byte, header.PayloadLength()-header.Length()-uint32(filenameLength)-2)
	read, err := io.ReadFull(r.Reader, payload)
	if err != nil {
		return nil, err
	}

	if len(payload) != read {
		return nil, fmt.Errorf("Payload : expected [%d], got [%d]", len(payload), read)
	}

	return &FileBlock{
		BlockHeader: header,
		FileName:    string(filename),
		Payload:     payload,
	}, nil
}

// ReadRawBlock reads any block type payload
func (r *SRR) ReadRawBlock(header BlockHeader) (*RawBlock, error) {
	payload := make([]byte, header.PayloadLength()-header.Length())
	read, err := io.ReadFull(r.Reader, payload)
	if err != nil {
		return nil, err
	}

	if len(payload) != read {
		return nil, fmt.Errorf("Payload : expected [%d], got [%d]", len(payload), read)
	}

	return &RawBlock{
		BlockHeader: header,
		Payload:     payload,
	}, nil
}

// ReadAll reads all blocks from SRR
func (r *SRR) ReadAll() error {
	for {
		blk, err := r.ReadBlock()
		if err != nil {
			return err
		}

		if blk == nil {
			return nil
		}

		r.Blocks = append(r.Blocks, blk)
	}
}

// BlockHeader block header interface
type BlockHeader interface {
	String() string
	Length() uint32
	PayloadLength() uint32
	BlockType() byte
}

// BaseBlockHeader common block header
type BaseBlockHeader struct {
	CRC           uint16
	blockType     byte
	Flags         uint16
	payloadLength uint16
}

// LargeBlockHeader block header with extended payload size
type LargeBlockHeader struct {
	*BaseBlockHeader
	addLength uint32
}

func (bh *BaseBlockHeader) String() string {
	return fmt.Sprintf("Block header type [0x%02X] - Payload size [%d] - Flags [0x%02X]", bh.BlockType(), bh.PayloadLength(), bh.Flags)
}

// Length returns block header size
func (bh *BaseBlockHeader) Length() uint32 {
	return 7
}

// PayloadLength returns total block size
func (bh *BaseBlockHeader) PayloadLength() uint32 {
	return uint32(bh.payloadLength)
}

// BlockType returns block type
func (bh *BaseBlockHeader) BlockType() byte {
	return bh.blockType
}

func (bh *LargeBlockHeader) String() string {
	return fmt.Sprintf("Large block header type [0x%02X] - Payload size [%d] - Flags [0x%02X]", bh.BlockType(), bh.PayloadLength(), bh.Flags)
}

// Length returns block header size
func (bh *LargeBlockHeader) Length() uint32 {
	return 11
}

// PayloadLength returns total block size
func (bh *LargeBlockHeader) PayloadLength() uint32 {
	return uint32(bh.payloadLength) + bh.addLength
}

// BlockType returns block type
func (bh *LargeBlockHeader) BlockType() byte {
	return bh.blockType
}

// Block interface
type Block interface {
	String() string
}

// HeaderBlock is BlockTypeSRRHeader header + payload
type HeaderBlock struct {
	BlockHeader
	AppName string
}

// FileBlock is BlockTypeFile header + payload
type FileBlock struct {
	BlockHeader
	FileName string
	Payload  []byte
}

// RawBlock is any block type header + payload
type RawBlock struct {
	BlockHeader
	Payload []byte
}

func (b *HeaderBlock) String() string {
	return fmt.Sprintf("HeaderBlock - Header: %s - AppName: %s", b.BlockHeader, b.AppName)
}

func (b *FileBlock) String() string {
	return fmt.Sprintf("FileBlock - Header: %s - Filename: %s", b.BlockHeader, b.FileName)
}

func (b *RawBlock) String() string {
	return fmt.Sprintf("RawBlock - Header: %s - Payload length: %d", b.BlockHeader, len(b.Payload))
}
