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
	"encoding/binary"
	"io"
)

const xx = 0xff

var hexTable = [256]byte{
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x00
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x10
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x20
	00, 01, 02, 03, 04, 05, 06, 07, 8, 0x9, xx, xx, xx, xx, xx, xx, // 0x30
	xx, 10, 11, 12, 13, 14, 15, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x40
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x50
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x60
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x70
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x80
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x90
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xa0
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xb0
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xc0
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xd0
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xe0
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xf0
}

// hexDecode returns a slice of bytes decoded from hexadecimal digits
// in s and their sum.  If buf has sufficient capacity, it's used for
// storage.
func hexDecode(buf []byte, s []byte) ([]byte, byte, error) {
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
		hi, lo := hexTable[s[i<<1]], hexTable[s[i<<1+1]]
		if hi|lo == 0xff {
			return nil, 0, ErrSyntax
		}
		buf[i] = hi<<4 | lo
		sum += hi<<4 | lo
	}
	return buf, sum, nil
}

// parser is an IHEX parser.  Format is set in ix, which also holds
// the result of parsing.  base is zero for 8-bit format, Segment Base
// Address for 16-bit and Upper Linear Base Address for 32-bit.
type parser struct {
	ix      *IHex         // result
	mask    uint32        // address mask
	base    uint32        // Linear or Segment Base Address
	hiBase  bool          // base is near top of address space
	segBase bool          // Base Address is Segment
	head    [dataOff]byte // header buffer
	data    []byte        // data buffer
}

// split splits data at at, capping the head.
func split(data []byte, at uint16) ([]byte, []byte) {
	return data[:at:at], data[at:]
}

// add adds data to the chunks.
func (p *parser) add(addr uint16, data []byte) []byte {
	if len(data) != 0 {
		a := (p.base + uint32(addr)) & p.mask
		if p.hiBase {
			// If data overflows the address space, wrap to 0.
			if uint32(-len(data))&p.mask < a {
				var cc Chunk
				data, cc.Data = split(data, uint16(-a))
				p.ix.Chunks.add(cc)
			}
		}
		c := p.ix.Chunks.add(Chunk{a, data})
		if &c.Data[0] == &data[0] {
			data = nil
		}
	}
	return data
}

// parseLine parses an IHEX record and applies it to p.ix.  It returns
// ErrChecksum, ErrFormat, ErrRecord or ErrSyntax on invalid input and
// io.EOF on End of File record.
func (p *parser) parseLine(s []byte) error {
	const dataOffs = 1 + dataOff*2
	if len(s) < dataOffs+2 || len(s)&1 == 0 || s[0] != ':' {
		return ErrSyntax
	}

	// parse the record, verify CHKSUM
	var (
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
	} else if len(p.data) != int(p.head[lenOff])+1 {
		return ErrSyntax
	}
	p.data = p.data[:len(p.data)-1]
	addr := binary.BigEndian.Uint16(p.head[addrOff:])
	typ := p.head[typeOff]

	// handle Data record
	if typ == dataRec {
		if len(p.data) != 0 {
			// If data goes past the end of the segment, and the
			// format is 16-bit or the segment base address is
			// set, wrap at the segment boundary.  Either part
			// can also wrap at the end of the address space.
			if p.segBase && uint16(-len(p.data)) < addr {
				var dd []byte
				p.data, dd = split(p.data, -addr)
				p.add(0, dd)
			}
			p.data = p.add(addr, p.data)
		}
		return nil
	}

	// check RECTYP, RECLEN and LOAD OFFSET, handle End of File record
	const reclen = "\x00\x00\x02\x04\x02\x04"
	if int(typ) >= len(reclen) {
		return ErrRecord
	} else if p.head[lenOff] != reclen[typ] || addr != 0 {
		return ErrSyntax
	} else if typ == eofRec {
		return io.EOF
	}

	// handle other record types.  check format.
	if format := Format16Bit + typ>>2; p.ix.Format == FormatAuto {
		if p.ix.InFormat < format {
			p.ix.InFormat = format
		}
	} else if p.ix.Format < format {
		return ErrFormat
	}
	var n uint32
	for _, v := range p.data {
		n = n<<8 | uint32(v)
	}
	switch typ {
	case extSegmentAddrRec:
		p.base = n << 4
		p.hiBase = p.base+(0xffff+0xff) > p.mask
		p.segBase = true
	case startSegmentAddrRec:
		p.ix.StartSegment = n
		p.ix.Start = (n>>16<<4 + n&0x0000ffff) & 0x000fffff
		p.ix.StartSet = true
	case extLinearAddrRec:
		p.base = n << 16
		p.hiBase = p.base == 0xffff0000
		p.segBase = false
	case startLinearAddrRec:
		p.ix.Start = n
		p.ix.StartSegment = 0
		p.ix.StartSet = true
	default:
		return ErrRecord
	}
	return nil
}

// Reader provides a simple interface for reading an IHEX file from an
// underlying reader.  It reads the whole file at the first Read,
// ReadStart, ReadStartSegment or Seek call.
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
	} else if padTo < 0 || padTo > sizeLimit[format&3] {
		return nil, ErrRange
	}
	return &Reader{r: r, format: format, end: padTo, gapFill: gapFill}, nil
}

// load reads an IHEX file from the underlying reader if it has not
// yet been read.
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
			if e := ix.Chunks[len(ix.Chunks)-1].end(); r.end < e {
				r.end = e
			}
		}
	}
	return nil
}

// Read reads from the address space represented by r.  Read returns
// io.EOF at the end of address space or ErrRange out of the address
// space.
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
	if rem := int(r.end - r.pos); n > rem {
		n = rem
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
			r.pos += size
			buf = buf[size:]
		}
		size := copy(buf, v.Data[r.pos-int64(v.Addr):])
		r.pos += int64(size)
		buf = buf[size:]
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
// set.  If the start address is segmented, it's converted to linear.
func (r *Reader) ReadStart() (uint32, error) {
	if err := r.load(); err != nil {
		return 0, err
	}
	return r.ix.Start, nil
}

// ReadStartSegment returns the start segment address, or zero if it
// has not been set.
func (r *Reader) ReadStartSegment() (uint32, error) {
	if err := r.load(); err != nil {
		return 0, err
	}
	return r.ix.StartSegment, nil
}

// Seek causes the next Read to return data from the specified
// address.  Seek implements the io.Seeker interface.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	if err := r.load(); err != nil {
		return 0, err
	}
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
