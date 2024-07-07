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
programmer to write data to memory locations (hereby referred to as
"the address space") and set certain registers ("the start address"),
along with record types this package only handles internally (EOF and
extended addressing).  As these records may appear in a file in any
order and are defined to have peculiar corner cases, this package only
presents the user with a simplified view of the address space, losing
details of a particular representation on input and generating
conservative output.

IHEX files come in three formats.  The format termed "8-bit" or
"I8HEX" has, naturally, contiguous 16-bit address space (64KB),
"16-bit"/"I16HEX" has crazy Intel-segmeted 20-bit address space (1MB),
and "32-bit"/"I32HEX" has 32-bit (4GB) addressing which is contiguous
but the high 16 bits of the address are still set separately.

# Input

The parser uses bufio.Scanner, and thus may overread from the
underlying reader.  It reads the whole file at once until an End of
File record is encountered, resulting in the address space looking as
described under (*ChunkList).Normalize.

The parser rejects records of RECTYP that is unknown or invalid for
the given format, and records of RECTYP other than Data with non-zero
LOAD OFFSET.

The parser uses one Base Address, whose value and type is set by the
most recent Extended Segment Address or Extended Linear Address
record.  The initial zero base is a Segment Base Address with 16-bit
input and Linear otherwise.  When the base is Segment, Data records
spanning segment boundaries are wrapped at the end of the segment to
the beginning thereof.  Data past the end of the address space are
wrapped to zero.

A Start Linear Address record sets the start address to its value.
Start Segment Address sets it to the absolute value, losing the detail
of the segmentation.  The original segmented representation is
available via IHex.StartSegment or (*Reader).ReadStartSegment; for
Linear addresses it is set to zero.

# Output

The writer never generates Data records crossing addresses divisible
by the given data record length, which must be a power of two and
defaults to 16.  Writes are buffered until such address boundary is
reached or a Writer method other than Write is called, causing the
write buffer to be flushed.  (*IHex).WriteTo calls (*Writer).Seek
before writing each Chunk.

Segment addresses are generated with the segment/offset split at 64 KB
boundaries, with the bottom 12 bits of the segment set to zero.
IHex.StartSegment and (*Writer).WriteStartSegment set the start
segment address, preserving segmentation.  In all other cases Linear
addresses are used in 32-bit format.
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
	FormatAuto  = iota // I32HEX; (*IHex).ReadFrom: detect format
	Format8Bit         // I8HEX format, 16-bit address space
	Format16Bit        // I16HEX format, 20-bit address space
	Format32Bit        // I32HEX format, 32-bit address space
)

// address space sizes for formats
var sizeLimit = [...]int64{1 << 32, 1 << 16, 1 << 20, 1 << 32}

// record types
const (
	dataRec             byte = iota // Data
	eofRec                          // End of File
	extSegmentAddrRec               // Extended Segment Address
	startSegmentAddrRec             // Start Segment Address
	extLinearAddrRec                // Extended Linear Address
	startLinearAddrRec              // Start Linear Address
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
	ErrStart    = errors.New("ihex: invalid start address")
	ErrSyntax   = errors.New("ihex: invalid syntax")
)

type SyntaxError struct {
	Err    error  // ErrChecksum, ErrFormat, ErrRecord or ErrSyntax
	Format byte   // Active IHEX format
	Line   int    // input line number, or 0 for missing EOF record
	Record string // input line, or "" for missing EOF record
}

var formatName = []string{"unspecified", "I8HEX", "I16HEX", "I32HEX"}

// Error returns the error formatted as one of:
//
//	"ihex: <invalid syntax/invalid record type/checksum error> on line <n>"
//	"ihex: invalid record for <unspecified/I8HEX/I16HEX/I32HEX> format on line <n>"
//	"ihex: missing EOF record"
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
	case int64(over.Addr) == under.end(): // optimise common case
		under.Data = append(under.Data, over.Data...)
		return under
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
// sorted slice cl, returning the merged Chunk.
func (cl *ChunkList) add(c Chunk) Chunk {
	if len(c.Data) == 0 {
		return c
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
	return c
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
// data in cl is written to it sequentially.  Subsequent writes to a
// location already written to overwrite whole bytes.
//
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
	// Format sets the file format.  Legal formats are FormatAuto,
	// Format8Bit, Format16Bit and Format32Bit.  FormatAuto is
	// equivalent to Format32Bit, but InFormat is used.
	Format byte

	// InFormat is used if Format is FormatAuto.  ReadFrom sets
	// InFormat to Format16Bit or Format32Bit if input contains
	// records specific to those formats.  WriteTo uses InFormat
	// as the output format.
	InFormat byte

	// DataRecLen is the maximum number of bytes in a Data
	// record length generated by WriteTo.  Must be a power
	// of two or 0.  In the latter case the default length of
	// 16 is used.
	DataRecLen byte

	// Start is the linear start address.  If the active format is
	// Format32Bit, Start represents the contents of EIP on 80386.
	// If it is Format16Bit, WriteTo will segment Start on a 64 KB
	// boundary; the top 12 bits must be zero.
	Start uint32

	// StartSegment is the segmented start address, representing
	// the pair of registers CS:IP on 8086.
	StartSegment uint32

	// StartSet indicates that Start has been set by
	// ReadFrom, or should be written by WriteTo even if it's
	// zero.
	StartSet bool

	// Chunks are the data written to the address space.
	Chunks ChunkList
}

/*
ReadFrom reads an IHEX file from r into ix.  ReadFrom returns nil on
success, ErrArgs if ix.Format is invalid, an error from r on read
errors or a SyntaxError on invalid input.  ReadFrom may overread r.

ReadFrom adds the data from r to ix.Chunks, setting it to a list of
programmed data areas as described under (*ChunkList).Normalize.  Any
data in the byte arrays underlying Chunks may be overwritten.  If
ix.Format is FormatAuto (zero value), ix.InFormat is set to
Format16Bit or Format32Bit if records specific to those formats appear
in the input file.

When a Start Segment Address or Start Linear Address record is
encountered, ix.StartSet is set to true.  In the former case
ix.StartSegment is set to the value and ix.Start to its 20 bit linear
representation, in the latter ix.Start is set to the value and
ix.StartSegment to zero.
*/
func (ix *IHex) ReadFrom(r io.Reader) error {
	if ix.Format > Format32Bit {
		return ErrArgs
	}
	var (
		p = parser{
			ix:      ix,
			mask:    uint32(sizeLimit[ix.Format&3]) - 1,
			hiBase:  ix.Format == Format8Bit,
			segBase: ix.Format == Format16Bit,
		}
		s    = bufio.NewScanner(r)
		line int
	)
	ix.Chunks.Normalize()
	for s.Scan() {
		line++
		if err := p.parseLine(s.Bytes()); err != nil {
			if err == io.EOF {
				return nil
			}
			return SyntaxError{
				Err:    err,
				Format: ix.Format,
				Line:   line,
				Record: s.Text(),
			}
		}
	}
	if err := s.Err(); err != nil {
		return err
	}
	return SyntaxError{Err: ErrSyntax}
}

// WriteTo writes data from cl to w in order.
func (cl ChunkList) WriteTo(w io.WriteSeeker) error {
	for _, v := range cl {
		if _, err := w.Seek(int64(v.Addr), io.SeekStart); err != nil {
			return err
		}
		if _, err := w.Write(v.Data); err != nil {
			return err
		}
	}
	return nil
}

// WriteTo writes data from ix to an IHEX file, using a Writer with
// parameters specified by ix.Format/ix.InFormat and ix.DataRecLength.
// ix.Chunks are written in order, flushing the write buffer between
// Chunks.  If ix.Start or ix.StartSegment is not zero or ix.StartSet
// is true, WriteTo sets the start address.  To set Start Segment
// Address in a 32-bit file, ix.Start must be zero and ix.StartSegment
// non-zero.
func (ix *IHex) WriteTo(w io.Writer) error {
	format := ix.Format
	if format == FormatAuto {
		format = ix.InFormat
	}
	xw, err := NewWriter(w, format, ix.DataRecLen)
	if err != nil {
		return err
	}
	if err = ix.Chunks.WriteTo(xw); err != nil {
		return err
	}
	if ix.StartSegment != 0 && (ix.Start == 0 || format == Format16Bit) {
		if err = xw.WriteStartSegment(ix.StartSegment); err != nil {
			return err
		}
	} else if ix.StartSet || ix.Start != 0 {
		if err = xw.WriteStart(ix.Start); err != nil {
			return err
		}
	}
	return xw.Close()
}
