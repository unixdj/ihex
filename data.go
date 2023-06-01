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

/*
Package ihex implements access to Intel HEX files.

IHEX files consist of records representing instructions for a PROM
programmer to write data to memory locations (referred to here as "the
address space") and set certain registers ("the start address"), along
with record types this package only handles internally (EOF and extended
addressing).  As these records may appear in a file in any order and
are defined to have peculiar corner cases, this package only presents
the user a simplified view of the address space, losing details of a
particular representation on input and generating conservative output.
Documentation for (*IHex).ReadFrom describes the abstraction in more
detail.

IHEX files come in three formats.  The format termed "8-bit" has,
naturally, contiguous 16-bit address space (64KB), "16-bit" format has
crazy Intel-segmeted 20-bit address space (1MB) and "32-bit" has 32-bit
(4GB) addressing which is contiguous but the high 16 bits of the address
are still set separately.  This package only allows Extended Segment
Address and Start Segment Address records in 16-bit files and Extended
Linear Address and Start Linear Address records in 32-bit files.
*/
package ihex

import (
	"bufio"
	"errors"
	"io"
	"sort"
	"strconv"
)

// IHEX file formats
const (
	FormatAuto  = iota // Auto-detect format
	Format8Bit         // I8HEX format, 16-bit address space
	Format16Bit        // I16HEX format, 20-bit address space
	Format32Bit        // I32HEX format, 32-bit address space
)

// record types
const (
	dataRec             = iota // Data
	eofRec                     // End of File
	extSegmentAddrRec          // Extended Segment Address
	startSegmentAddrRec        // Start Segment Address
	extLinearAddrRec           // Extended Linear Address
	startLinearAddrRec         // Start Linear Address
)

// field offsets within record
const (
	lenOff  = 0 // RECLEN
	addrOff = 1 // LOAD OFFSET
	typeOff = 3 // RECTYP
	dataOff = 4 // INFO or DATA
	// last byte: CHKSUM
)

var (
	ErrArgs     = errors.New("ihex: invalid arguments")
	ErrChecksum = errors.New("ihex: checksum error")
	ErrClosed   = errors.New("ihex: writer is closed")
	ErrFormat   = errors.New("ihex: invalid record for format")
	ErrRange    = errors.New("ihex: address out of range")
	ErrRecord   = errors.New("ihex: unknown record type")
	ErrSyntax   = errors.New("ihex: invalid syntax")
)

type SyntaxError struct {
	Err    error  // ErrChecksum, ErrFormat, ErrRecord or ErrSyntax
	Line   int    // 0 for missing EOF record, otherwise input line number
	Format byte   // Active IHEX format
	Record string // "" for missing EOF record, otherwise input line
}

var formatName = []string{"unspecified", "I8HEX", "I16HEX", "I32HEX"}

// Error returns the error formatted as one of:
//     "ihex: <invalid syntax/checksum error> on line <n>"
//     "ihex: invalid record for <unspecified/I8HEX/I16HEX/I32HEX> format on line <n>"
//     "ihex: missing EOF record"
func (e SyntaxError) Error() string {
	switch {
	case e.Line == 0:
		return "ihex: missing EOF record"
	case e.Err == ErrFormat:
		return "ihex: invalid record for " + formatName[e.Format] +
			" format on line " + strconv.Itoa(e.Line)
	default:
		return e.Err.Error() + " on line " + strconv.Itoa(e.Line)
	}
}

// Chunk represents a contiguous area in the IHEX address space.
type Chunk struct {
	Addr uint32
	Data []byte
}

// end returns the address at the end of c.
func (c Chunk) end() int64 {
	return int64(c.Addr) + int64(len(c.Data))
}

// overlaps returns true if two Chunks overlap or are adjacent.
// XXX misnomer
func (c Chunk) overlaps(cc Chunk) bool {
	return int64(c.Addr) <= cc.end() && int64(cc.Addr) <= c.end()
}

// over returns a Chunk with data from two adjacent or overlapping Chunks,
// over and under, the former taking the precedence over the latter.
// over may overwrite data in the Chunks.
func (over Chunk) over(under Chunk) Chunk {
	switch {
	case over.Addr <= under.Addr && over.end() >= under.end():
		return over
	case over.Addr < under.Addr:
		over.Data = append(over.Data,
			under.Data[over.end()-int64(under.Addr):]...)
		return over
	case over.end() > under.end():
		under.Data = append(under.Data[:over.Addr-under.Addr],
			over.Data...)
		return under
	default:
		copy(under.Data[over.Addr-under.Addr:], over.Data)
		return under
	}
}

// ChunkList is a slice of Chunks.
type ChunkList []Chunk

// find finds the first Chunk in a sorted slice cl whose end is
// at or after addr.
func (cl ChunkList) find(addr int64) int {
	return sort.Search(len(cl),
		func(i int) bool { return cl[i].end() >= addr })
}

// add adds data in c to the address space represented by a
// sorted slice cl.
func (cl *ChunkList) add(c Chunk) {
	if len(c.Data) == 0 {
		return
	}
	if i := cl.find(int64(c.Addr)); i == len(*cl) {
		*cl = append(*cl, c)
	} else {
		j := i
		for j < len(*cl) && c.overlaps((*cl)[j]) {
			c = c.over((*cl)[j])
			j++
		}
		if j != i+1 {
			*cl = append((*cl)[:i+1], (*cl)[j:]...)
		}
		(*cl)[i] = c
	}
}

// normal returns true if cl is a sorted list of nonadjacent
// non-zero-legth Chunks.
func (cl ChunkList) normal() bool {
	end := int64(-1)
	for _, v := range cl {
		if int64(v.Addr) <= end || len(v.Data) == 0 {
			return false
		}
		end = v.end()
	}
	return true
}

// Normalize turns cl into a sorted list of nonadjacent non-zero-legth
// Chunks representing the address space as it would look after the
// data in cl would be written to it sequentially.
// Normalize may mutate data in place.
func (cl *ChunkList) Normalize() {
	if cl.normal() {
		return
	}
	sorted := make(ChunkList, 0, len(*cl))
	for _, v := range *cl {
		sorted.add(v)
	}
	*cl = sorted
}

// IHex represents the contents of an IHEX file.
type IHex struct {
	// Format describes the file format.  Legal formats for
	// writing are Format8Bit, Format16Bit and Format32Bit;
	// for reading, FormatAuto is also legal.
	Format byte

	// DataRecLen is the maximum number of bytes in a Data
	// record length generated by WriteTo.  Must be a power
	// of two or 0.  In the latter case the default length of
	// 16 is used.
	DataRecLen byte

	// Start is the "start address".  For 32-bit format it
	// symbolizes the contents of EIP on 80386, and for
	// 16-bit, the pair of 16-bit registers CS:IP on 8086.
	// 8-bit format does not support setting a start address.
	Start uint32

	// Chunks are the data written to the address space.
	Chunks ChunkList
}

/*
ReadFrom reads an IHEX file from r, filling ix.  ReadFrom returns nil
on success, ErrSyntax or ErrChecksum in case of invalid input
and anything else on read errors.  ReadFrom may overread r.

ix.Format defines the format of the file being read.  If ReadFrom is
called with the ix.Format equal to FormatAuto (zero value) and a
record specific to 16-bit or 32-bit format is encoutered,
ix.Format is set accordingly.  Due to different semantics of Data records
spanning 64KB address boundaries, such records are disallowed with
FormatAuto (however, one shouldn't expect to encounter such records
the wild).

ix.Chunks is set to a sorted list of nonadjacent contiguous data areas
representing programmed areas in a (potentially sparse) address space of
a target machine, with later writes overwriting results of earlier ones.
This does not necessarily represent the behaviour of actual hardware;
e.g., a location in flash memory contains conjunction (binary AND) of
all values written to it since last erase.  If ix.Chunks is non-empty
before calling ReadFrom, it is normalized to allow interleaving reads
from several files with direct data manipulation.

If any Start Segment/Linear Address records are encountered, ix.Start
is set to the value in the last such record.
*/
func (ix *IHex) ReadFrom(r io.Reader) error {
	var (
		p    = &parser{data: ix}
		s    = bufio.NewScanner(r)
		line int
	)
	ix.Chunks.Normalize()
	for s.Scan() {
		line++
		if err := p.parseLine(s.Text()); err != nil {
			if err == io.EOF {
				return nil
			}
			return SyntaxError{
				Err:    err,
				Line:   line,
				Format: ix.Format,
				Record: s.Text(),
			}
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return SyntaxError{Err: ErrSyntax}
}

// WriteTo writes data from ix to an IHEX file.  Using a Writer of the
// format specified by ix.Format (which must not be FormatAuto) and
// data record length of ix.DataRecLength, it first writes ix.Chunks
// in order without any normalization, followed by ix.Start unless
// it's zero.  ix.Start must be zero for 8-bit format files.
func (ix *IHex) WriteTo(w io.Writer) error {
	xw, err := NewWriter(w, ix.Format, ix.DataRecLen)
	if err != nil {
		return err
	}
	for _, v := range ix.Chunks {
		if _, err = xw.Seek(int64(v.Addr), 0); err != nil {
			return err
		}
		if _, err = xw.Write(v.Data); err != nil {
			return err
		}
	}
	if ix.Start != 0 {
		if err = xw.WriteStart(ix.Start); err != nil {
			return err
		}
	}
	return xw.Close()
}
