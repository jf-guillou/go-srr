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
	if header.BlockType != BlockTypeSRRHeader {
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
func (r *SRR) ReadBlockHeader() (*BlockHeader, error) {

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
	var blockLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &blockLength); err != nil {
		return nil, err
	}

	return &BlockHeader{
		CRC:         crc,
		BlockType:   blockType,
		Flags:       flags,
		BlockLength: blockLength,
	}, nil
}

// ReadBlockPayload reads payload content according to header block type
func (r *SRR) ReadBlockPayload(header *BlockHeader) (Block, error) {
	switch header.BlockType {
	case BlockTypeSRRHeader:
		return r.ReadHeaderBlock(header)
	case BlockTypeFile:
		return r.ReadFileBlock(header)
	case BlockTypePackedFile:
		return r.ReadPackedBlock(header)
	default:
		return r.ReadRawBlock(header)
	}
}

// ReadHeaderBlock reads BlockTypeSRRHeader payload
func (r *SRR) ReadHeaderBlock(header *BlockHeader) (*HeaderBlock, error) {
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
func (r *SRR) ReadFileBlock(header *BlockHeader) (*FileBlock, error) {
	var payloadSize uint32
	if header.Flags&0x8000 != 0 {
		if err := binary.Read(r.Reader, binary.LittleEndian, &payloadSize); err != nil {
			return nil, err
		}
	}

	var filenameLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &filenameLength); err != nil {
		return nil, err
	}

	filename := make([]byte, filenameLength)
	if err := binary.Read(r.Reader, binary.LittleEndian, filename); err != nil {
		return nil, err
	}

	payload := make([]byte, payloadSize)
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

// ReadPackedBlock reads BlockTypePackedFile payload
func (r *SRR) ReadPackedBlock(header *BlockHeader) (*PackedBlock, error) {
	var packedSize uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &packedSize); err != nil {
		return nil, err
	}

	var unpackedSize uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &unpackedSize); err != nil {
		return nil, err
	}

	os, err := r.Reader.ReadByte()
	if err != nil {
		return nil, err
	}

	var fileCRC uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &fileCRC); err != nil {
		return nil, err
	}

	var timestamp uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &timestamp); err != nil {
		return nil, err
	}

	rarVersion, err := r.Reader.ReadByte()
	if err != nil {
		return nil, err
	}

	method, err := r.Reader.ReadByte()
	if err != nil {
		return nil, err
	}

	var nameLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &nameLength); err != nil {
		return nil, err
	}

	var fileAttributes uint32
	if err := binary.Read(r.Reader, binary.LittleEndian, &fileAttributes); err != nil {
		return nil, err
	}

	var highPackSize uint32
	if header.Flags&0x100 > 0 {
		if err := binary.Read(r.Reader, binary.LittleEndian, &highPackSize); err != nil {
			return nil, err
		}
	}

	var highUnpackSize uint32
	if header.Flags&0x100 > 0 {
		if err := binary.Read(r.Reader, binary.LittleEndian, &highUnpackSize); err != nil {
			return nil, err
		}
	}

	name := make([]byte, nameLength)
	if err := binary.Read(r.Reader, binary.LittleEndian, name); err != nil {
		return nil, err
	}

	salt := make([]byte, 8)
	if header.Flags&0x400 > 0 {
		if err := binary.Read(r.Reader, binary.LittleEndian, salt); err != nil {
			return nil, err
		}
	}

	if header.Flags&0x1000 > 0 {
		return nil, fmt.Errorf("Flags & 0x1000")
	}

	return &PackedBlock{
		BlockHeader:       header,
		PackedSize:        uint64(highPackSize<<32 + packedSize),
		UnpackedSize:      uint64(highUnpackSize<<32 + unpackedSize),
		OS:                os,
		FileCRC:           fileCRC,
		Timestamp:         timestamp,
		RARVersion:        rarVersion,
		CompressionMethod: method,
		Name:              string(name),
		Salt:              salt,
	}, nil
}

// ReadRawBlock reads any block type payload
func (r *SRR) ReadRawBlock(header *BlockHeader) (*RawBlock, error) {
	payload := make([]byte, header.BlockLength-7)
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

// BlockHeader common block header
type BlockHeader struct {
	CRC         uint16
	BlockType   byte
	Flags       uint16
	BlockLength uint16
}

func (bh *BlockHeader) String() string {
	return fmt.Sprintf("Block header type [0x%02X] - Payload size [%d] - Flags [0x%02X]", bh.BlockType, bh.BlockLength, bh.Flags)
}

// Block interface
type Block interface {
	String() string
}

// HeaderBlock is BlockTypeSRRHeader header + payload
type HeaderBlock struct {
	*BlockHeader
	AppName string
}

// FileBlock is BlockTypeFile header + payload
type FileBlock struct {
	*BlockHeader
	FileName string
	Payload  []byte
}

// PackedBlock is BlockTypePackedFile header + payload
type PackedBlock struct {
	*BlockHeader
	PackedSize        uint64
	UnpackedSize      uint64
	OS                byte
	FileCRC           uint32
	Timestamp         uint32
	RARVersion        byte
	CompressionMethod byte
	Name              string
	Salt              []byte
}

// RawBlock is any block type header + payload
type RawBlock struct {
	*BlockHeader
	Payload []byte
}

func (b *HeaderBlock) String() string {
	return fmt.Sprintf("HeaderBlock - Header: %s - AppName: %s", b.BlockHeader, b.AppName)
}

func (b *FileBlock) String() string {
	return fmt.Sprintf("FileBlock - Header: %s - Filename: %s", b.BlockHeader, b.FileName)
}

func (b *PackedBlock) String() string {
	return fmt.Sprintf("PackedBlock - Header: %s - Filename: %s", b.BlockHeader, b.Name)
}

func (b *RawBlock) String() string {
	return fmt.Sprintf("RawBlock - Header: %s - Payload length: %d", b.BlockHeader, len(b.Payload))
}
