package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"time"
)

type CPU struct {
	Header CPUHeader
	Traces []CPUTrace
	Total  uint64
}

type CPUHeader struct {
	Version uint64
	Period  time.Duration
	Extra   []uint64
}

type CPUTrace struct {
	PC    []uint64
	Count uint64
}

func (p *CPU) Len() int           { return len(p.Traces) }
func (p *CPU) Less(i, j int) bool { return p.Traces[i].Count > p.Traces[j].Count }
func (p *CPU) Swap(i, j int)      { p.Traces[i], p.Traces[j] = p.Traces[j], p.Traces[i] }

func ReadCPU(r io.Reader) (*CPU, error) {
	var p CPU

	var order binary.ByteOrder = binary.LittleEndian
	read := func(r io.Reader) (uint64, error) {
		var x uint32
		err := binary.Read(r, order, &x)
		return uint64(x), err
	}
	reverse := func(i uint64) uint64 {
		return (i>>24)&0x000000FF |
			(i>>16)&0x0000FF00 |
			(i<<16)&0x00FF0000 |
			(i<<24)&0xFF000000
	}
	size := uint64(binary.Size(uint32(0)))

	n1, err := read(r)
	if err != nil {
		return nil, err
	}
	if n1 != 0 {
		panic("corrupt cpu profile")
	}
	n2, err := read(r)
	if err != nil {
		return nil, err
	}
	if n2 == 0 {
		read = func(r io.Reader) (uint64, error) {
			var x uint64
			err := binary.Read(r, order, &x)
			return x, err
		}
		reverse = func(i uint64) uint64 {
			return (i>>56)&0x00000000000000FF |
				(i>>48)&0x000000000000FF00 |
				(i>>40)&0x0000000000FF0000 |
				(i>>32)&0x00000000FF000000 |
				(i<<32)&0x000000FF00000000 |
				(i<<40)&0x0000FF0000000000 |
				(i<<48)&0x00FF000000000000 |
				(i<<56)&0xFF00000000000000
		}
		size = uint64(binary.Size(uint64(0)))
		n2, err = read(r)
		if err != nil {
			return nil, err
		}
	}
	if n2>>(size*8/2) != 0 {
		order = binary.BigEndian
		n2 = reverse(n2)
	}
	if n2 < 3 {
		panic("corrupt cpu profile")
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n2*size)); err != nil {
		return nil, err
	}
	p.Header.Version, err = read(&buf)
	if err != nil {
		return nil, err
	}
	if p.Header.Version != 0 {
		panic("corrupt cpu profile")
	}
	period, err := read(&buf)
	if err != nil {
		return nil, err
	}
	p.Header.Period = time.Microsecond * time.Duration(period)
	readAll := func() (all []uint64) {
		for {
			n, err := read(&buf)
			if err != nil {
				if err == io.EOF {
					return
				}
				panic(err)
			}
			all = append(all, n)
		}
	}
	p.Header.Extra = readAll()

	count := make(map[string]uint64)

	for {
		n1, err := read(r)
		if err != nil {
			if err == io.EOF {
				fmt.Println("Warning: incomplete cpu profile")
				break
			}
			return nil, err
		}
		n2, err := read(r)
		if err != nil {
			panic(err)
		}
		buf.Reset()
		if _, err := io.CopyN(&buf, r, int64(n2*size)); err != nil {
			panic(err)
		}
		if n1 == 0 && n2 == 1 {
			// special "stop" sequence (0, 1, 0)
			found := false
			for _, b := range buf.Bytes() {
				if b != 0 {
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
		count[buf.String()] += n1
		p.Total += n1
	}

	p.Traces = make([]CPUTrace, 0, len(count))
	for s, c := range count {
		buf.Reset()
		buf.WriteString(s)
		p.Traces = append(p.Traces, CPUTrace{
			Count: c,
			PC:    readAll(),
		})
	}
	sort.Sort(&p)
	return &p, nil
}
