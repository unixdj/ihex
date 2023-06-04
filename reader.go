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
	"encoding/binary"
	"io"
)

// parser is an IHEX parser.  Format is set in ix, which also holds
// the result of parsing.  base is zero for 8-bit format, Segment Base
// Address for 16-bit and Upper Linear Base Address for 32-bit.
type parser struct {
	ix   *IHex         // result
	base uint16        // Segment or Upper Linear Base Address
	head [dataOff]byte // header buffer
	data []byte        // data buffer
}

// fullAddr returns the full address composed from p.base and addr.
func (p *parser) fullAddr(addr uint16) uint32 {
	if p.ix.Format == Format16Bit {
		return (uint32(p.base)<<4 + uint32(addr)) & (1<<20 - 1)
	}
	return uint32(p.base)<<16 | uint32(addr)
}

var hexmap = [...]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 0x30 - 0x37
	0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0x38 - 0x3f
	0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, // 0x40 - 0x47
}

// hexDigit returns the value of the hexadecimal digit d, or 0xff on
// error.
func hexDigit(d byte) byte {
	if d -= '0'; d < byte(len(hexmap)) {
		return hexmap[d]
	}
	return 0xff
}

// hexDecode returns a slice of bytes decoded from hexadecimal digits
// in s and their sum.  If buf's capacity is sufficient, it's used for
// storage.
func hexDecode(buf []byte, s string) ([]byte, byte, error) {
	if sz := len(s) >> 1; cap(buf) < sz {
		buf = make([]byte, sz)
	} else {
		buf = buf[:sz]
	}
	if len(s) != len(buf)*2 {
		return nil, 0, ErrSyntax
	}
	var sum byte
	for i := range buf {
		hi, lo := hexDigit(s[i<<1]), hexDigit(s[i<<1+1])
		if hi|lo == 0xff {
			return nil, 0, ErrSyntax
		}
		buf[i] = hi<<4 | lo
		sum += hi<<4 | lo
	}
	return buf, sum, nil
}

// parseLine parses an IHEX record and applies it to p.ix.  It returns
// ErrChecksum, ErrFormat, ErrRecord or ErrSyntax on invalid input and
// io.EOF on End Of File record.
func (p *parser) parseLine(s string) error {
	const dataOffs = 1 + dataOff*2
	if len(s) < dataOffs+2 || len(s)&1 == 0 || s[0] != ':' {
		return ErrSyntax
	}
	var (
		format     = byte(Format32Bit)
		hsum, dsum byte
		err        error
	)
	if _, hsum, err = hexDecode(p.head[:], s[1:dataOffs]); err != nil {
		return err
	}
	if p.data, dsum, err = hexDecode(p.data, s[dataOffs:]); err != nil {
		return err
	}
	if hsum+dsum != 0 {
		return ErrChecksum
	}
	addr := binary.BigEndian.Uint16(p.head[addrOff:])
	if p.head[typeOff] != dataRec && addr != 0 ||
		len(p.data) != int(p.head[lenOff])+1 {
		return ErrSyntax
	}
	p.data = p.data[:len(p.data)-1]
	switch p.head[typeOff] {
	case dataRec:
		a := p.fullAddr(addr)
		if addr+uint16(len(p.data))-1 < addr {
			// For Data records whose data's addresses overflow
			// 16-bit register, in 8-bit and 32-bit format the data
			// are wrapped to zero at the end of the address space
			// (16- and 32-bit, respectively), and in 16-bit
			// format, at the end of the current segment to the
			// beginning thereof.
			var aa uint32
			switch {
			case p.ix.Format == FormatAuto:
				return ErrFormat
			case p.ix.Format != Format32Bit:
				aa = p.fullAddr(0)
				fallthrough
			case p.base == 0xffff:
				dd := make([]byte, addr+uint16(len(p.data)))
				copy(dd, p.data[-addr:])
				p.ix.Chunks.add(Chunk{aa, dd})
				p.data = p.data[:-addr]
			}
		}
		c := p.ix.Chunks.add(Chunk{a, p.data})
		if &c.Data[0] == &p.data[0] {
			p.data = nil
		}
		return nil
	case eofRec:
		if len(p.data) != 0 {
			return ErrSyntax
		}
		return io.EOF
	case extSegmentAddrRec:
		format = Format16Bit
		fallthrough
	case extLinearAddrRec:
		if len(p.data) != 2 {
			return ErrSyntax
		}
		p.base = binary.BigEndian.Uint16(p.data)
	case startSegmentAddrRec:
		format = Format16Bit
		fallthrough
	case startLinearAddrRec:
		if len(p.data) != 4 {
			return ErrSyntax
		}
		p.ix.Start = binary.BigEndian.Uint32(p.data)
		p.ix.StartSet = true
	default:
		return ErrRecord
	}
	if p.ix.Format != FormatAuto || p.ix.Format != format {
		return ErrFormat
	}
	p.ix.Format = format
	return nil
}

// Reader provides a simple interface for reading an IHEX file from an
// underlying reader.  It reads the whole file at the first Read or
// ReadStart call.
//
// Reader's Read method reads from a contiguous address space spanning
// from address 0 to the end address, which is normally the address
// immediately after the topmost byte written by the programmer, with
// gaps between written memory filled with zeros.  For readers created
// by NewPadReader, the end address is set to padTo if the latter is
// higher, and the filler byte is set to gapFill.
type Reader struct {
	r       io.Reader // reader
	format  byte      // format requested by caller
	ix      *IHex     // data
	err     error     // read error
	pos     int64     // reader position
	end     int64     // end address
	padTo   int64     // pad-to address
	gapFill byte      // filler byte
}

// NewReader returns a Reader reading from r.  format must be one of
// FormatAuto, Format8Bit, Format16Bit or Format32Bit.
func NewReader(r io.Reader, format byte) (*Reader, error) {
	return NewPadReader(r, format, 0, 0)
}

// NewPadReader returns a Reader reading from r.  The returned Reader
// has its address space padded to at least padTo, with any gaps
// filled with gapFill.
func NewPadReader(r io.Reader, format byte, padTo int64, gapFill byte) (*Reader, error) {
	if format > Format32Bit {
		return nil, ErrArgs
	} else if padTo < 0 || padTo > 1<<32 {
		return nil, ErrRange
	}
	return &Reader{r: r, format: format, padTo: padTo, gapFill: gapFill},
		nil
}

// load reads an IHEX file from an underlying reader if it has not yet
// been read.
func (r *Reader) load() error {
	if r.err != nil {
		return r.err
	}
	if r.ix == nil {
		ix := IHex{Format: r.format}
		if r.err = ix.ReadFrom(r.r); r.err != nil {
			return r.err
		}
		r.ix = &ix
		if len(ix.Chunks) != 0 {
			r.end = ix.Chunks[len(ix.Chunks)-1].end()
		}
		if r.end < r.padTo {
			r.end = r.padTo
		}
	}
	return nil
}

// Read reads from the address space represented by r.  Read returns
// io.EOF at the end of address space, ErrRange out of the address
// space or an error from (*IHex).ReadFrom on syntax or read errors.
func (r *Reader) Read(buf []byte) (int, error) {
	if err := r.load(); err != nil {
		return 0, err
	}
	if r.pos == r.end {
		return 0, io.EOF
	} else if r.pos > r.end {
		return 0, ErrRange
	}
	n := len(buf)
	if n > int(r.end-r.pos) {
		n = int(r.end - r.pos)
		buf = buf[:n]
	}
	for _, v := range r.ix.Chunks[r.ix.Chunks.find(r.pos):] {
		if int64(v.Addr) > r.pos {
			size := int64(v.Addr) - r.pos
			if size >= int64(len(buf)) {
				break
			}
			for i := range buf[:size] {
				buf[i] = r.gapFill
			}
			buf = buf[size:]
			r.pos += size
		}
		size := v.end() - r.pos
		if size == 0 {
			continue
		} else if size > int64(len(buf)) {
			size = int64(len(buf))
		}
		copy(buf[:size], v.Data[r.pos-int64(v.Addr):])
		buf = buf[size:]
		r.pos += size
		if len(buf) == 0 {
			return n, nil
		}
	}
	for i := range buf {
		buf[i] = r.gapFill
	}
	r.pos += int64(len(buf))
	return n, nil
}

// ReadStart returns the start address, or zero if it has not been
// set.  ReadStart may return an error from (*IHex).ReadFrom.
func (r *Reader) ReadStart() (uint32, error) {
	if err := r.load(); err != nil {
		return 0, err
	}
	return r.ix.Start, nil
}

// Seek causes the next Read to return data from the specified
// address.  Seek implements the io.Seeker interface.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.pos
	case io.SeekEnd:
		offset += r.end
	default:
		return r.pos, ErrRange
	}
	if offset < 0 {
		return r.pos, ErrRange
	}
	r.pos = offset
	return r.pos, nil
}
