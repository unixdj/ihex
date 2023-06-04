/*
 * Copyright (c) 2014-2015, 2020-2023 Vadim Vygonets <vadik@vygo.net>
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
	// colon, RECLEN + LOAD OFFSET + RECTYP, DATA, CHKSUM, newline
	maxLineLen = 1 + (dataOff+maxDataLen+1)*2 + 1

	hexDigits = "0123456789ABCDEF"
)

var sizeLimits = [...]int64{1 << 16, 1 << 16, 1 << 20, 1 << 32}

func hexEncodeByte(dst []byte, b byte) int {
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
	upper      uint16           // Upper Linear Base Address or Segment>>12
	end        int64            // topmost address written + 1
	dataRecLen int              // bytes per Data record
	bufLen     int              // bytes in data buffer
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
		dataRecLen: int(dataRecLen),
	}, nil
}

// writeRec writes a record of type typ.
func (w *Writer) writeRec(typ byte, addr uint16, data []byte) error {
	var (
		sum byte
		n   int
	)
	w.head[0] = byte(len(data))
	binary.BigEndian.PutUint16(w.head[1:], addr)
	w.head[3] = typ
	for _, v := range w.head {
		sum += v
	}
	for _, v := range data {
		sum += v
	}
	line := w.line[:]
	if sz := len(data)*2 + (len(w.head)*2 + 4); w.w.Available() >= sz {
		line = w.w.AvailableBuffer()[:sz]
	}
	line[n] = ':'
	n++
	n += hexEncode(line[n:], w.head[:])
	n += hexEncode(line[n:], data)
	n += hexEncodeByte(line[n:], -sum)
	line[n] = '\n'
	n++
	_, err := w.w.Write(line[:n])
	return err
}

// writeData writes a Data record, possibly preceeded by an
// Extended Segment/Linear Address record.
func (w *Writer) writeData(buf []byte) error {
	if upper := uint16(w.addr >> 16); upper != w.upper {
		if w.addr >= sizeLimits[w.format&3] {
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
	if w.bufLen != 0 {
		if err := w.writeData(w.buf[:w.bufLen]); err != nil {
			return err
		}
		w.bufLen = 0
	}
	return nil
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
		n = size
		w.bufLen += copy(w.buf[w.bufLen:], buf[:n])
		buf = buf[n:]
		if err := w.flush(); err != nil {
			return 0, err
		}
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

// WriteStart sets the start address to addr.
func (w *Writer) WriteStart(addr uint32) error {
	if w.closed {
		return ErrClosed
	} else if err := w.flush(); err != nil {
		return err
	}
	var typ byte
	switch w.format {
	case Format16Bit:
		typ = startSegmentAddrRec
	case Format32Bit:
		typ = startLinearAddrRec
	default:
		return ErrFormat
	}
	binary.BigEndian.PutUint32(w.buf[:], addr)
	return w.writeRec(typ, 0, w.buf[:4])
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
	if offset < 0 || offset > sizeLimits[w.format&3] {
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
