package srr

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	BlockTypeSRR      = 0x69
	BlockTypeFile     = 0x6A
	BlockTypeOsoHash  = 0x6B
	BlockTypePadding  = 0x6C
	BlockTypeRarFile  = 0x71
	BlockTypeRarStart = 0x72
	BlockTypeRarEnd   = 0x7B
)

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
	if header.BlockType() != BlockTypeSRR {
		return nil, errors.New("File is not a valid SRR archive")
	}

	// Reset reader
	f.Seek(0, io.SeekStart)
	srr.Reader.Reset(f)

	return srr, nil
}

type SRR struct {
	Reader   *bufio.Reader
	Filesize int64
	Blocks   []Block
}

func (r *SRR) String() string {
	return fmt.Sprintf("SRR file - Size [%d]", r.Filesize)
}

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

func (r *SRR) ReadBlock() (Block, error) {
	header, err := r.ReadBlockHeader()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	switch header.BlockType() {
	case BlockTypeSRR:
		srrBlock, err := r.ReadSRRBlock()
		if err != nil {
			return nil, err
		}

		srrBlock.BlockHeader = header
		return srrBlock, nil
	case BlockTypeFile:
		fileBlock, err := r.ReadFileBlock(header.PayloadLength() - header.Length())
		if err != nil {
			return nil, err
		}

		fileBlock.BlockHeader = header
		return fileBlock, nil
	default:
		rawBlock, err := r.ReadRawBlock(header.PayloadLength() - header.Length())
		if err != nil {
			return nil, err
		}

		rawBlock.BlockHeader = header
		return rawBlock, nil
	}
}

func (r *SRR) ReadSRRBlock() (*SRRBlock, error) {
	var appNameSize uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &appNameSize); err != nil {
		return nil, err
	}

	appName := make([]byte, appNameSize)
	if err := binary.Read(r.Reader, binary.LittleEndian, appName); err != nil {
		return nil, err
	}

	return &SRRBlock{
		AppName: string(appName),
	}, nil
}

func (r *SRR) ReadFileBlock(length uint32) (*FileBlock, error) {
	var filenameLength uint16
	if err := binary.Read(r.Reader, binary.LittleEndian, &filenameLength); err != nil {
		return nil, err
	}

	filename := make([]byte, filenameLength)
	if err := binary.Read(r.Reader, binary.LittleEndian, filename); err != nil {
		return nil, err
	}

	payload := make([]byte, length-uint32(filenameLength)-2)
	read, err := io.ReadFull(r.Reader, payload)
	if err != nil {
		return nil, err
	}

	if len(payload) != read {
		return nil, fmt.Errorf("Payload : expected [%d], got [%d]\n", len(payload), read)
	}

	return &FileBlock{
		FileName: string(filename),
		Payload:  payload,
	}, nil
}

func (r *SRR) ReadRawBlock(length uint32) (*RawBlock, error) {
	payload := make([]byte, length)
	read, err := io.ReadFull(r.Reader, payload)
	if err != nil {
		return nil, err
	}

	if len(payload) != read {
		return nil, fmt.Errorf("Payload : expected [%d], got [%d]\n", len(payload), read)
	}

	return &RawBlock{
		Payload: payload,
	}, nil
}

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

type BlockHeader interface {
	String() string
	Length() uint32
	PayloadLength() uint32
	BlockType() byte
}
type BaseBlockHeader struct {
	CRC           uint16
	blockType     byte
	Flags         uint16
	payloadLength uint16
}
type LargeBlockHeader struct {
	*BaseBlockHeader
	addLength uint32
}

func (bh *BaseBlockHeader) String() string {
	return fmt.Sprintf("Block header type [0x%02X] - Payload size [%d] - Flags [0x%02X]", bh.BlockType(), bh.PayloadLength(), bh.Flags)
}
func (bh *BaseBlockHeader) Length() uint32 {
	return 7
}
func (bh *BaseBlockHeader) PayloadLength() uint32 {
	return uint32(bh.payloadLength)
}
func (bh *BaseBlockHeader) BlockType() byte {
	return bh.blockType
}

func (bh *LargeBlockHeader) String() string {
	return fmt.Sprintf("Large block header type [0x%02X] - Payload size [%d] - Flags [0x%02X]", bh.BlockType(), bh.PayloadLength(), bh.Flags)
}
func (bh *LargeBlockHeader) Length() uint32 {
	return 11
}
func (bh *LargeBlockHeader) PayloadLength() uint32 {
	return uint32(bh.payloadLength) + bh.addLength
}
func (bh *LargeBlockHeader) BlockType() byte {
	return bh.blockType
}

type Block interface {
	String() string
}
type SRRBlock struct {
	BlockHeader
	AppName string
}
type FileBlock struct {
	BlockHeader
	FileName string
	Payload  []byte
}
type RawBlock struct {
	BlockHeader
	Payload []byte
}

func (b *SRRBlock) String() string {
	return fmt.Sprintf("SRRBlock - Header: %s - AppName: %s", b.BlockHeader, b.AppName)
}

func (b *FileBlock) String() string {
	return fmt.Sprintf("FileBlock - Header: %s - Filename: %s", b.BlockHeader, b.FileName)
}

func (b *RawBlock) String() string {
	return fmt.Sprintf("SRRBlock - Header: %s - Payload length: %d", b.BlockHeader, len(b.Payload))
}
