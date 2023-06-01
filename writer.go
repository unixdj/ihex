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
	"errors"
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

var (
	ErrChecksum = errors.New("ihex: checksum error")
	ErrClosed   = errors.New("ihex: writer is closed")
	ErrFormat   = errors.New("ihex: invalid format")
	ErrArgs     = errors.New("ihex: invalid arguments")
	ErrRange    = errors.New("ihex: address out of range")
	ErrSyntax   = errors.New("ihex: invalid syntax")
)

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

func sizeLimit(format byte) int64 {
	return [...]int64{1 << 16, 1 << 20, 1 << 32}[format-Format8Bit]
}

// Writer writes an IHEX file to an underlying writer.  Records are
// written in the order in which Writer's methods are called.  After
// all data are written to the Writer, Close must be called.
type Writer struct {
	w          io.Writer        // writer
	addr       int64            // write address
	segment    int64            // upper 16 bits of addr in last Data record written
	end        int64            // topmost address written + 1
	dataRecLen int              // bytes per Data record
	format     byte             // format
	closed     bool             // closed?
	buf        []byte           // data buffer
	head       [dataOff]byte    // header buffer
	line       [maxLineLen]byte // line buffer
}

// NewWriter retutrns a new Writer writing to w.  format defines the
// IHEX file format (which may not be FormatAuto).  dataRecLen is the
// maximum number of bytes in a Data record generated, which must be a
// power of two or 0.  In the latter case the default length of 16 is
// used.  If any argument is invalid, ErrArgs is returned as error.
func NewWriter(w io.Writer, format byte, dataRecLen byte) (*Writer, error) {
	if format == FormatAuto || format > Format32Bit ||
		dataRecLen&(dataRecLen-1) != 0 {
		return nil, ErrFormat
	}
	if dataRecLen == 0 {
		dataRecLen = defaultDataLen
	}
	xw := Writer{w: w, format: format, dataRecLen: int(dataRecLen)}
	return &xw, nil
}

// writeRec writes a record of type typ.
func (w *Writer) writeRec(typ byte, addr uint16, data []byte) error {
	var (
		sum byte
		n   int
	)
	w.head = [...]byte{byte(len(data)), byte(addr >> 8), byte(addr), typ}
	for _, v := range w.head {
		sum += v
	}
	for _, v := range data {
		sum += v
	}
	w.line[n] = ':'
	n++
	n += hexEncode(w.line[n:], w.head[:])
	n += hexEncode(w.line[n:], data)
	n += hexEncodeByte(w.line[n:], -sum)
	w.line[n] = '\n'
	n++
	_, err := w.w.Write(w.line[:n])
	return err
}

// writeData writes a Data record, possibly preceeded by an
// Extended Segment/Linear Address record.
func (w *Writer) writeData(buf []byte) error {
	var err error
	if segment := w.addr >> 16; segment != w.segment {
		if w.addr >= sizeLimit(w.format) {
			return ErrRange
		}
		if w.format == Format16Bit {
			err = w.writeRec(extSegmentAddrRec, 0,
				[]byte{byte(segment << 4), 0})
		} else {
			err = w.writeRec(extLinearAddrRec, 0,
				[]byte{byte(segment >> 8), byte(segment)})
		}
		if err != nil {
			return err
		}
		w.segment = segment
	}
	if err = w.writeRec(dataRec, uint16(w.addr), buf); err != nil {
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
	if len(w.buf) != 0 {
		if err := w.writeData(w.buf); err != nil {
			return err
		}
		w.buf = w.buf[:0]
	}
	return nil
}

// Write writes data from buf as Data records.  Extended Segment or
// Linear Address records are generated as needed.  Writes beyond the
// address space valid for the current format generate an error.  Data
// are written in chunks of up to the number of bytes set by the
// dataRecLen argument to NewWriter, never spanning a dataRecLen
// address boundary.  Writes are buffered as needed.
func (w *Writer) Write(buf []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	var (
		n    int
		size = w.dataRecLen
	)
	if w.addr&int64(w.dataRecLen-1) != 0 {
		size = int(-w.addr) & (w.dataRecLen - 1)
	}
	if len(w.buf) != 0 {
		n = size - len(w.buf)
		if n > len(buf) {
			n = len(buf)
		}
		w.buf = append(w.buf, buf[:n]...)
		buf = buf[n:]
		if len(w.buf) < size {
			return n, nil
		}
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
		w.buf = append(w.buf, buf...)
		n += len(buf)
	}
	return n, nil
}

// WriteStart sets the start address to addr.  If the format of w is
// Format32Bit, a Start Linear Address record is generated, setting
// EIP to addr.  For Format16Bit, the Start Segment Address written
// sets CS to the high 16 bits of addr and IP to its low 16 bits.
// Attempting to set a start address for a Format8Bit writer is an
// error.
func (w *Writer) WriteStart(addr uint32) error {
	if w.closed {
		return ErrClosed
	}
	if err := w.flush(); err != nil {
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
	w.buf = append(w.buf,
		byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
	err := w.writeRec(typ, 0, w.buf)
	w.buf = w.buf[:0]
	return err
}

// Seek causes the next Write to write data to the specified address
// in the address space.  Its arguments are compliant with the
// io.Seeker interface.  If the resulting address is out of the legal
// address space for w's format, an error is returned.  Seek flushes
// the write buffer but otherwise does not generate any records.
func (w *Writer) Seek(offset int64, whence int) (int64, error) {
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.flush(); err != nil {
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
	if offset < 0 || offset > sizeLimit(w.format) {
		return w.addr, ErrRange
	}
	w.addr = offset
	return w.addr, nil
}

// Close flushes data buffers of w and writes an EOF record to an
// underlying writer.  It may return non-nil if any of the writes
// fail.  After Close is called, further calls to Close will return
// nil, and calls to other methods of w will return ErrClosed as an
// error.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.flush(); err != nil {
		return err
	}
	return w.writeRec(eofRec, 0, nil)
}
