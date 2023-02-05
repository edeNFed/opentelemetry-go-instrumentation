package process

import (
	"debug/elf"
	"errors"
	"fmt"
	"github.com/hashicorp/go-version"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/process/ptrace"
	"os"
)

const (
	mapSize = 12582912
)

type TargetDetails struct {
	PID               int
	Functions         []*Func
	GoVersion         *version.Version
	Libraries         map[string]string
	AllocationDetails *AllocationDetails
}

type AllocationDetails struct {
	Addr    uint64
	EndAddr uint64
}

type Func struct {
	Name          string
	Offset        uint64
	ReturnOffsets []uint64
}

func (t *TargetDetails) IsRegistersABI() bool {
	regAbiMinVersion, _ := version.NewVersion("1.17")
	return t.GoVersion.GreaterThanOrEqual(regAbiMinVersion)
}

func (t *TargetDetails) GetFunctionOffset(name string) (uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.Offset, nil
		}
	}

	return 0, fmt.Errorf("could not find offset for function %s", name)
}

func (t *TargetDetails) GetFunctionReturns(name string) ([]uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.ReturnOffsets, nil
		}
	}

	return nil, fmt.Errorf("could not find returns for function %s", name)
}

func (a *processAnalyzer) remoteMmap(pid int, mapSize uint64) (uint64, error) {
	program, err := ptrace.Trace(pid, log.Logger)
	if err != nil {
		log.Logger.Error(err, "Failed to attach ptrace", "pid", pid)
		return 0, err
	}

	defer program.Detach()
	addr, err := program.Mmap(mapSize, 0)
	if err != nil {
		log.Logger.Error(err, "Failed to mmap", "pid", pid)
		return 0, err
	}

	return addr, nil
}

func (a *processAnalyzer) Analyze(pid int, relevantFuncs map[string]interface{}) (*TargetDetails, error) {
	result := &TargetDetails{
		PID: pid,
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()
	elfF, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}

	goVersion, modules, err := a.getModuleDetails(elfF)
	if err != nil {
		return nil, err
	}
	result.GoVersion = goVersion
	result.Libraries = modules

	addr, err := a.remoteMmap(pid, mapSize)
	if err != nil {
		log.Logger.Error(err, "Failed to mmap")
		return nil, err
	}
	log.Logger.V(0).Info("mmaped remote memory", "start_addr", fmt.Sprintf("%X", addr),
		"end_addr", fmt.Sprintf("%X", addr+mapSize))

	result.AllocationDetails = &AllocationDetails{
		Addr:    addr,
		EndAddr: addr + mapSize,
	}

	if err != nil {
		return nil, err
	}
	symbols, err := elfF.Symbols()
	if err != nil {
		return nil, err
	}

	for _, f := range symbols {
		if _, exists := relevantFuncs[f.Name]; exists {
			offset, err := getFuncOffset(elfF, f)
			if err != nil {
				return nil, err
			}

			returns, err := findFuncReturns(elfF, f, offset)
			if err != nil {
				return nil, err
			}

			log.Logger.V(0).Info("found relevant function for instrumentation", "function", f.Name, "returns", len(returns))
			function := &Func{
				Name:          f.Name,
				Offset:        offset,
				ReturnOffsets: returns,
			}

			result.Functions = append(result.Functions, function)
		}
	}

	return result, nil
}

func getFuncOffset(f *elf.File, symbol elf.Symbol) (uint64, error) {
	var sections []*elf.Section

	for i := range f.Sections {
		if f.Sections[i].Flags == elf.SHF_ALLOC+elf.SHF_EXECINSTR {
			sections = append(sections, f.Sections[i])
		}
	}

	if len(sections) == 0 {
		return 0, fmt.Errorf("function %q not found in file", symbol)
	}

	var execSection *elf.Section
	for m := range sections {
		sectionStart := sections[m].Addr
		sectionEnd := sectionStart + sections[m].Size
		if symbol.Value >= sectionStart && symbol.Value < sectionEnd {
			execSection = sections[m]
			break
		}
	}

	if execSection == nil {
		return 0, errors.New("could not find symbol in executable sections of binary")
	}

	return uint64(symbol.Value - execSection.Addr + execSection.Offset), nil
}

func findFuncReturns(elfFile *elf.File, sym elf.Symbol, functionOffset uint64) ([]uint64, error) {
	textSection := elfFile.Section(".text")
	if textSection == nil {
		return nil, errors.New("could not find .text section in binary")
	}

	lowPC := sym.Value
	highPC := lowPC + sym.Size
	offset := lowPC - textSection.Addr
	buf := make([]byte, int(highPC-lowPC))

	readBytes, err := textSection.ReadAt(buf, int64(offset))
	if err != nil {
		return nil, fmt.Errorf("could not read text section: %w", err)
	}
	data := buf[:readBytes]
	instructionIndices, err := findRetInstructions(data)
	if err != nil {
		return nil, fmt.Errorf("error while scanning instructions: %w", err)
	}

	// Add the function lowPC to each index to obtain the actual locations
	newLocations := make([]uint64, len(instructionIndices))
	for i, instructionIndex := range instructionIndices {
		newLocations[i] = instructionIndex + functionOffset
	}

	return newLocations, nil
}
