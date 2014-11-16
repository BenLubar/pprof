package main

import (
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"
)

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
