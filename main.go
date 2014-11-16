package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/pprof"
	"strings"
	"time"
)

var (
	cpuprofile = flag.String("cpuprofile", "", "")
)

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if err = pprof.StartCPUProfile(f); err != nil {
			panic(err)
		}
		defer pprof.StopCPUProfile()
	}

	size := uint64(binary.Size(uint64(0)))
	var r *bufio.Reader
	var table *gosym.Table

	if t, err := Symbols(flag.Arg(0)); err != nil {
		panic(err)
	} else {
		table = t
	}
	if f, err := os.Open(flag.Arg(1)); err != nil {
		panic(err)
	} else {
		defer f.Close()
		r = bufio.NewReader(f)
	}

	var n1, n2 uint64
	if err := binary.Read(r, binary.LittleEndian, &n1); err != nil {
		panic(err)
	}
	if n1 != 0 {
		panic("corrupt cpu profile")
	}
	var buf bytes.Buffer
	if err := binary.Read(r, binary.LittleEndian, &n2); err != nil {
		panic(err)
	}
	if n2 < 3 {
		panic("corrupt cpu profile")
	}
	if _, err := io.CopyN(&buf, r, int64(n2*size)); err != nil {
		panic(err)
	}
	var version uint64
	if err := binary.Read(&buf, binary.LittleEndian, &version); err != nil {
		panic(err)
	}
	if version != 0 {
		panic("corrupt cpu profile")
	}
	if err := binary.Read(&buf, binary.LittleEndian, &n1); err != nil {
		panic(err)
	}
	period := time.Microsecond * time.Duration(n1)

	count := make(map[string]uint64)
	var total uint64

	for {
		buf.Reset()
		if err := binary.Read(r, binary.LittleEndian, &n1); err != nil {
			if err == io.EOF {
				fmt.Println("Warning: incomplete cpu profile")
				break
			}
			panic(err)
		}
		if err := binary.Read(r, binary.LittleEndian, &n2); err != nil {
			panic(err)
		}
		if _, err := io.CopyN(&buf, r, int64(n2*size)); err != nil {
			panic(err)
		}
		if n1 == 0 && n2 == 1 {
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
		total += n1
	}

	fmt.Println(total, "total samples", time.Duration(total)*period)
	fmt.Println(len(count), "distinct stacks")
	var max uint64
	for _, c := range count {
		if max < c {
			max = c
		}
	}
	fmt.Println(max, "max samples", time.Duration(max)*period)
	for s, c := range count {
		if max == c {
			sr := strings.NewReader(s)
			for {
				var pc uint64
				if err := binary.Read(sr, binary.LittleEndian, &pc); err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				file, line, fn := table.PCToLine(pc)
				fmt.Printf("%s:%d %v+%x\n", file, line, fn.Name, pc-fn.Entry)
			}
		}
	}
}

var symbolHelpers = []func(filename string) (symdat, pclndat []byte, textstart uint64, err error){
	symbolHelperElf,
	symbolHelperPe,
	symbolHelperMacho,
}

func Symbols(filename string) (*gosym.Table, error) {
	var errs []string
	for _, f := range symbolHelpers {
		symdat, pclndat, textstart, err := f(filename)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		return gosym.NewTable(symdat, gosym.NewLineTable(pclndat, textstart))
	}

	return nil, fmt.Errorf("no symbols could be loaded from %q\n%s", filename, strings.Join(errs, "\n"))
}

func symbolHelperElf(filename string) (symdat, pclndat []byte, textstart uint64, err error) {
	f, err := elf.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	symdat, err = f.Section(".gosymtab").Data()
	if err != nil {
		return
	}

	pclndat, err = f.Section(".gopclntab").Data()
	if err != nil {
		return
	}

	textstart = f.Section(".text").Addr

	return
}

func symbolHelperPe(filename string) (symdat, pclndat []byte, textstart uint64, err error) {
	f, err := pe.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	symdat, err = f.Section(".gosymtab").Data()
	if err != nil {
		return
	}

	pclndat, err = f.Section(".gopclntab").Data()
	if err != nil {
		return
	}

	textstart = uint64(f.Section(".text").VirtualAddress)

	return
}

func symbolHelperMacho(filename string) (symdat, pclndat []byte, textstart uint64, err error) {
	f, err := macho.Open(filename)
	if err != nil {
		return
	}
	defer f.Close()

	symdat, err = f.Section(".gosymtab").Data()
	if err != nil {
		return
	}

	pclndat, err = f.Section(".gopclntab").Data()
	if err != nil {
		return
	}

	textstart = f.Section(".text").Addr

	return
}
