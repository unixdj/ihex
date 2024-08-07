/*
 * Copyright (c) 2014-2015, 2020-2024 Vadim Vygonets <vadik@vygo.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package ihex

import (
	"bufio"
	"encoding/binary"
	"io"
)

const (
	defaultDataLen = 0x10 // default data bytes per Data record generated
	maxDataLen     = 0x80 // maximum data bytes per Data record generated

	// maximim length of a record as text:
	// colon, RECLEN + LOAD OFFSET + RECTYP, DATA, CHKSUM, CR/LF
	maxLineLen = 1 + (dataOff+maxDataLen+1)*2 + 2
)

func hexEncodeByte(dst []byte, b byte) int {
	const hexDigits = "0123456789ABCDEF"
	_ = dst[1]
	dst[0], dst[1] = hexDigits[b>>4], hexDigits[b&0xf]
	return 2
}

func hexEncode(dst, src []byte) int {
	for i, v := range src {
		hexEncodeByte(dst[i*2:], v)
	}
	return len(src) * 2
}

// Writer writes an IHEX file to an underlying writer.  Records are
// written in the order in which Writer's methods are called.  After
// all data are written to the Writer, Close must be called.
type Writer struct {
	w          *bufio.Writer    // writer
	addr       int64            // write address
	end        int64            // topmost address written + 1
	limit      int64            // size of address space
	dataRecLen int              // bytes per Data record
	bufLen     int              // bytes in data buffer
	upper      uint16           // Upper Segment/Linear Base Address
	format     byte             // format
	closed     bool             // closed?
	extBuf     [2]byte          // extended address buffer
	head       [dataOff]byte    // header buffer
	buf        [maxDataLen]byte // data buffer
	line       [maxLineLen]byte // line buffer
}

// NewWriter returns a new Writer writing to w.  format defines the
// IHEX file format.  dataRecLen is the maximum number of bytes in a
// Data record generated, which must be a power of two or 0.  In the
// latter case the default length of 16 is used.  If any argument is
// invalid, ErrArgs is returned as error.
func NewWriter(w io.Writer, format byte, dataRecLen byte) (*Writer, error) {
	if format > Format32Bit || dataRecLen&(dataRecLen-1) != 0 {
		return nil, ErrArgs
	}
	if dataRecLen == 0 {
		dataRecLen = defaultDataLen
	}
	return &Writer{
		w:          bufio.NewWriter(w),
		format:     format,
		limit:      sizeLimit[format&3],
		dataRecLen: int(dataRecLen),
	}, nil
}

// writeRec writes a record of type typ.
func (w *Writer) writeRec(typ byte, addr uint16, data []byte) error {
	w.head[lenOff] = byte(len(data))
	binary.BigEndian.PutUint16(w.head[addrOff:], addr)
	w.head[typeOff] = typ
	var sum byte
	for _, v := range w.head {
		sum += v
	}
	for _, v := range data {
		sum += v
	}
	line := w.w.AvailableBuffer()
	if line = line[:cap(line)]; cap(line) < len(data)*2+dataOff*2+5 {
		line = w.line[:]
	}
	var n int
	line[n] = ':'
	n++
	n += hexEncode(line[n:], w.head[:])
	n += hexEncode(line[n:], data)
	n += hexEncodeByte(line[n:], -sum)
	line[n], line[n+1] = '\r', '\n'
	n += 2
	_, err := w.w.Write(line[:n])
	return err
}

// writeData writes a Data record, possibly preceeded by an
// Extended Segment/Linear Address record.
func (w *Writer) writeData(buf []byte) error {
	if upper := uint16(w.addr >> 16); upper != w.upper {
		if w.addr >= w.limit {
			return ErrRange
		}
		w.upper = upper
		typ := extLinearAddrRec
		if w.format == Format16Bit {
			typ = extSegmentAddrRec
			upper <<= 12
		}
		binary.BigEndian.PutUint16(w.extBuf[:], upper)
		if err := w.writeRec(typ, 0, w.extBuf[:]); err != nil {
			return err
		}
	}
	if err := w.writeRec(dataRec, uint16(w.addr), buf); err != nil {
		return err
	}
	w.addr += int64(len(buf))
	if w.end < w.addr {
		w.end = w.addr
	}
	return nil
}

// flush flushes the write buffer.
func (w *Writer) flush() error {
	var err error
	if w.bufLen != 0 {
		err = w.writeData(w.buf[:w.bufLen])
		w.bufLen = 0
	}
	return err
}

// Write writes data from buf to r.  Writes are buffered as needed.
func (w *Writer) Write(buf []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	var (
		n    int
		size = -(int(w.addr) + w.bufLen | -w.dataRecLen)
	)
	if w.bufLen != 0 && len(buf) >= size {
		w.bufLen += copy(w.buf[w.bufLen:], buf[:size])
		buf = buf[size:]
		if err := w.flush(); err != nil {
			return 0, err
		}
		n = size
		size = w.dataRecLen
	}
	for len(buf) >= size {
		if err := w.writeData(buf[:size]); err != nil {
			return n, err
		}
		n += size
		buf = buf[size:]
		size = w.dataRecLen
	}
	if len(buf) != 0 {
		w.bufLen += copy(w.buf[w.bufLen:], buf)
		n += len(buf)
	}
	return n, nil
}

// writeStart sets the start address to addr.
func (w *Writer) writeStart(addr uint32, typ byte) error {
	if w.format == Format8Bit {
		return ErrFormat
	} else if err := w.flush(); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(w.buf[:], addr)
	return w.writeRec(typ, 0, w.buf[:4])
}

// WriteStart sets the start linear address in 32-bit files or start
// segment address in 16-bit files.  WriteStart returns ErrFormat if
// the format is Format8Bit, and ErrStart if the format is Format16Bit
// and addr is wider than 20 bit.
func (w *Writer) WriteStart(addr uint32) error {
	var typ byte = startLinearAddrRec
	if w.closed {
		return ErrClosed
	} else if w.format == Format16Bit {
		if addr&0xfff00000 != 0 {
			return ErrStart
		}
		addr = addr&0xffff0000<<12 | addr&0x0000ffff
		typ = startSegmentAddrRec
	}
	return w.writeStart(addr, typ)
}

// WriteStartSegment sets the start segment address to addr.
func (w *Writer) WriteStartSegment(addr uint32) error {
	if w.closed {
		return ErrClosed
	}
	return w.writeStart(addr, startLinearAddrRec)
}

// Seek causes the next Write to write data to the specified address
// in the address space.  Seek flushes the data buffer, but otherwise
// does not generate any records.  Seek implements the io.Seeker
// interface.
func (w *Writer) Seek(offset int64, whence int) (int64, error) {
	if w.closed {
		return 0, ErrClosed
	} else if err := w.flush(); err != nil {
		return 0, err
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += w.addr
	case io.SeekEnd:
		offset += w.end
	default:
		return w.addr, ErrRange
	}
	if offset < 0 || offset > w.limit {
		return w.addr, ErrRange
	}
	w.addr = offset
	return w.addr, nil
}

// Close flushes the data buffer and writes an EOF record to the
// underlying writer.  After Close is called, further calls to Close
// will return nil, and calls to other methods of w will return
// ErrClosed as error.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.flush(); err != nil {
		return err
	}
	if err := w.writeRec(eofRec, 0, nil); err != nil {
		return err
	}
	return w.w.Flush()
}
