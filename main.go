package main

import (
	"bufio"
	"debug/gosym"
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
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

	var cpu *CPU
	var table *gosym.Table

	if t, err := Symbols(flag.Arg(0)); err != nil {
		panic(err)
	} else {
		table = t
	}
	if f, err := os.Open(flag.Arg(1)); err != nil {
		panic(err)
	} else {
		cpu, err = ReadCPU(bufio.NewReader(f))
		f.Close()
		if err != nil {
			panic(err)
		}
	}

	fmt.Println(cpu.Total, "total samples", time.Duration(cpu.Total)*cpu.Header.Period)
	fmt.Println(len(cpu.Traces), "distinct stacks")
	max := cpu.Traces[0].Count
	fmt.Println(max, "max samples", time.Duration(max)*cpu.Header.Period)
	for i := range cpu.Traces {
		if cpu.Traces[i].Count != max {
			break
		}
		for _, pc := range cpu.Traces[i].PC {
			file, line, fn := table.PCToLine(pc)
			fmt.Printf("%s:%d %v+%x\n", file, line, fn.Name, pc-fn.Entry)
		}
	}
}
