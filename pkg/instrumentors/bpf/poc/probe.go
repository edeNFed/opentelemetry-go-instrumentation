package poc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/context"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/events"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/goroutine/bpffs"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
	"golang.org/x/sys/unix"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bpf ./bpf/probe.bpf.c -- -I/usr/include/bpf -I$BPF_IMPORT

type FunctionInput struct {
	StrParam    [100]byte
}

type mainWorkerInstrumentor struct {
	bpfObjects   *bpfObjects
	uprobe       link.Link
	eventsReader *perf.Reader
}

func New() *mainWorkerInstrumentor {
	return &mainWorkerInstrumentor{}
}

func (m *mainWorkerInstrumentor) LibraryName() string {
	return "main/worker"
}

func (m *mainWorkerInstrumentor) FuncNames() []string {
	return []string{"main.worker"}
}

func (m *mainWorkerInstrumentor) Load(ctx *context.InstrumentorContext) error {
	logger := log.Logger.WithName("main/worker-instrumentor")
	spec, err := loadBpf()
	if err != nil {
		logger.Error(err, "error in loadBpf")
		return err
	}

	m.bpfObjects = &bpfObjects{}
	err = spec.LoadAndAssign(m.bpfObjects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.GoRoutinesMapDir,
		},
	})
	if err != nil {
		logger.Error(err, "error in load and assign")
		return err
	}

	offset, err := ctx.TargetDetails.GetFunctionOffset(m.FuncNames()[0])
	if err != nil {
		logger.Error(err, "error in get func offset")
		return err
	}

	up, err := ctx.Executable.Uprobe("", m.bpfObjects.UprobeMainWorker, &link.UprobeOptions{
		Offset: offset,
	})
	if err != nil {
		logger.Error(err, "error in uprobe creation")
		return err
	}

	m.uprobe = up

	rd, err := perf.NewReader(m.bpfObjects.Events, os.Getpagesize())
	if err != nil {
		logger.Error(err, "error in perf newreader")
		return err
	}
	m.eventsReader = rd

	return nil
}

func (m *mainWorkerInstrumentor) Run(eventsChan chan<- *events.Event) {
	logger := log.Logger.WithName("main/worker-instrumentor")
	var event FunctionInput
	for {
		record, err := m.eventsReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.Error(err, "error reading from perf reader")
			continue
		}

		if record.LostSamples != 0 {
			logger.V(0).Info("perf event ring buffer full", "dropped", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error(err, "error parsing perf event")
			continue
		}

		m.convertEvent(&event)
	}
}

func (m *mainWorkerInstrumentor) convertEvent(e *FunctionInput) {
	param := unix.ByteSliceToString(e.StrParam[:])
	fmt.Printf("Got param: %s\n", param)
}

func (m *mainWorkerInstrumentor) Close() {
	log.Logger.V(0).Info("closing main/worker instrumentor")
	if m.eventsReader != nil {
		m.eventsReader.Close()
	}

	if m.uprobe != nil {
		m.uprobe.Close()
	}

	if m.bpfObjects != nil {
		m.bpfObjects.Close()
	}
}
