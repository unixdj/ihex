// Copyright 2014 Vadim Vygonets
//
// This package is free software. It comes without any warranty, to
// the extent permitted by applicable law. You can redistribute it
// and/or modify it under the terms of the Do What The Fuck You Want
// To Public License, Version 2, as published by Sam Hocevar. See
// the LICENSE file or http://sam.zoy.org/wtfpl/ for more details.

package ihex

import (
	"encoding/binary"
	"io"
	"strings"
)

// parser is an IHEX parser.  Format is set in data, which also holds
// the result of parsing.  segment is zero for 8-bit format, Segment
// Base Address for 16-bit and Upper Linear Base Address for 32-bit.
type parser struct {
	data    *IHex  // result
	segment uint16 // Segment Base Address or Upper Linear Base Address
}

// fullAddr returns the full address composed from p.segment and
// addr.
func (p *parser) fullAddr(addr uint16) uint32 {
	if p.data.Flags&FormatMask == Format16bit {
		return (uint32(p.segment)<<4 + uint32(addr)) & (1<<20 - 1)
	}
	return uint32(p.segment)<<16 | uint32(addr)
}

// setFormat sets the format of p to format if applicable, and returns
// ErrSyntax otherwise.
func (p *parser) setFormat(format byte) error {
	switch p.data.Flags & FormatMask {
	case FormatAuto:
		p.data.Flags |= format
	case format:
	default:
		return ErrSyntax
	}
	return nil
}

// setSegment sets the segment base or upper linear address from data.
// If data is of invalid length or the parser's file format is
// incompatible with format, ErrSyntax is returned.  If the parser's
// format is FormatAuto, it will be set to format.
func (p *parser) setSegment(format byte, data []byte) error {
	if len(data) != 2 {
		return ErrSyntax
	}
	if err := p.setFormat(format); err != nil {
		return err
	}
	p.segment = binary.BigEndian.Uint16(data)
	return nil
}

// setStart sets the start segment/linear address from data.  If data
// is of invalid length or the parser's file format is incompatible
// with format, ErrSyntax is returned.  If the parser's format is
// FormatAuto, it will be set to format.
func (p *parser) setStart(format byte, data []byte) error {
	if len(data) != 4 {
		return ErrSyntax
	}
	if err := p.setFormat(format); err != nil {
		return err
	}
	p.data.Start = binary.BigEndian.Uint32(data)
	return nil
}

func hexDecodeString(s string) ([]byte, error) {
	if len(s)&1 != 0 {
		return nil, ErrSyntax
	}
	buf := make([]byte, len(s)>>1)
	for i := range buf {
		n := strings.IndexByte(hexDigits, s[0])<<4 |
			strings.IndexByte(hexDigits, s[1])
		if n&^0xff != 0 {
			return nil, ErrSyntax
		}
		buf[i] = byte(n)
		s = s[2:]
	}
	return buf, nil
}

// parseLine parses an IHEX record and applies it to p.data.  It
// returns io.EOF on End Of File record and ErrSyntax or ErrChecksum
// on invalid input.
func (p *parser) parseLine(s string) error {
	if len(s) < 1+(dataOff+1)<<1 || s[0] != ':' {
		return ErrSyntax
	}
	buf, err := hexDecodeString(s[1:])
	if err != nil {
		return err
	}
	var (
		addr = binary.BigEndian.Uint16(buf[addrOff:])
		data = buf[dataOff : len(buf)-1]
		sum  byte
	)
	for _, v := range buf {
		sum += v
	}
	if sum != 0 {
		return ErrChecksum
	}
	if buf[typeOff] != dataRec && addr != 0 ||
		len(data) != int(buf[lenOff]) {
		return ErrSyntax
	}
	switch buf[typeOff] {
	case dataRec:
		if addr+uint16(len(data))-1 < addr {
			// For Data records whose data's addresses overflow
			// 16-bit register, in 8-bit and 32-bit format the data
			// are wrapped to zero at the end of the address space
			// (16- and 32-bit, respectively), and in 16-bit
			// format, at the end of the current segment to the
			// beginning thereof.
			var c Chunk
			switch {
			case p.data.Flags&FormatMask == FormatAuto:
				return ErrSyntax
			case p.data.Flags&FormatMask != Format32bit:
				c.Addr = p.fullAddr(0)
				fallthrough
			case p.segment == 0xffff:
				c.Data = append(c.Data, data[-addr:]...)
				p.data.Chunks.add(c)
				data = data[:-addr]
			}
		}
		p.data.Chunks.add(Chunk{p.fullAddr(addr), data})
	case eofRec:
		if len(data) != 0 {
			return ErrSyntax
		}
		return io.EOF
	case extSegmentAddrRec:
		return p.setSegment(Format16bit, data)
	case startSegmentAddrRec:
		return p.setStart(Format16bit, data)
	case extLinearAddrRec:
		return p.setSegment(Format32bit, data)
	case startLinearAddrRec:
		return p.setStart(Format32bit, data)
	default:
		return ErrSyntax
	}
	return nil
}

// Reader provides a simple interface for reading an IHEX file from an
// underlying reader.  It reads the whole file by calling
// (*IHex).ReadFrom on the first Read or ReadStart call.  A slightly
// more detailed represetation of IHEX file is provided by type IHex.
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
	data    *IHex     // data
	err     error     // read error
	pos     int64     // reader position
	end     int64     // end address
	padTo   int64     // pad-to address
	gapFill byte      // filler byte
}

// NewReader returns a Reader reading from r.  format must be one of
// FormatAuto, Format8bit, Format16bit or Format32bit.
func NewReader(r io.Reader, format byte) (*Reader, error) {
	return NewPadReader(r, format, 0, 0)
}

// NewPadReader returns a Reader reading from r.  The returned Reader
// has its address space padded to at least padTo, with any gaps
// filled with gapFill.
func NewPadReader(r io.Reader, format byte, padTo int64, gapFill byte) (*Reader, error) {
	if format&^FormatMask != 0 {
		return nil, ErrFormat
	}
	if padTo < 0 || padTo > 1<<32 {
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
	if r.data == nil {
		ix := IHex{Flags: r.format}
		if r.err = ix.ReadFrom(r.r); r.err != nil {
			return r.err
		}
		r.data = &ix
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
	for _, v := range r.data.Chunks[r.data.Chunks.find(r.pos):] {
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
	return r.data.Start, nil
}

// Seek causes the next Read to return data from the specified
// address.  Seek returns ErrRange if whence is invalid or the
// resulting address is negative.  Seeking to an address beyond the
// end of the address space represented by r will cause next Read to
// return ErrRange.  Seek is compatible with io.Seeker.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
	case 1:
		offset += r.pos
	case 2:
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
