package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strconv"
    "syscall"
    "time"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -cc clang -cflags $BPF_CFLAGS bpf ./pkg/signal_blocker.c

type SignalEvent struct {
    TargetPID uint32
    SourcePID uint32
    Signal    uint32
    Blocked   uint32
    Timestamp uint64
}

type SignalBlocker struct {
    objs       bpfObjects
    link       link.Link
    reader     *ringbuf.Reader
    blockedMap *ebpf.Map
}

func NewSignalBlocker() (*SignalBlocker, error) {
    // Remove memory limit for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("failed to remove memlock: %w", err)
    }

    // Load pre-compiled programs and maps into kernel
    spec, err := loadBpf()
    if err != nil {
        return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
    }

    objs := bpfObjects{}
    if err := spec.LoadAndAssign(&objs, nil); err != nil {
        return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
    }

    // Attach LSM program
    l, err := link.AttachLSM(link.LSMOptions{
        Program: objs.TaskKillHook,
    })
    if err != nil {
        objs.Close()
        return nil, fmt.Errorf("failed to attach LSM program: %w", err)
    }

    // Setup ring buffer reader
    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        l.Close()
        objs.Close()
        return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
    }

    return &SignalBlocker{
        objs:       objs,
        link:       l,
        reader:     rd,
        blockedMap: objs.BlockedPids,
    }, nil
}

func (sb *SignalBlocker) Close() error {
    if sb.reader != nil {
        sb.reader.Close()
    }
    if sb.link != nil {
        sb.link.Close()
    }
    return sb.objs.Close()
}

func (sb *SignalBlocker) BlockPID(pid uint32) error {
    key := pid
    value := uint8(1)
    
    if err := sb.blockedMap.Put(&key, &value); err != nil {
        return fmt.Errorf("failed to add PID %d to blocked list: %w", pid, err)
    }
    
    fmt.Printf("✓ Now blocking signals to PID %d\n", pid)
    return nil
}

func (sb *SignalBlocker) UnblockPID(pid uint32) error {
    key := pid
    
    if err := sb.blockedMap.Delete(&key); err != nil {
        return fmt.Errorf("failed to remove PID %d from blocked list: %w", pid, err)
    }
    
    fmt.Printf("✓ No longer blocking signals to PID %d\n", pid)
    return nil
}

func (sb *SignalBlocker) ListBlockedPIDs() error {
    fmt.Println("Currently blocked PIDs:")
    
    var key uint32
    var value uint8
    iter := sb.blockedMap.Iterate()
    
    found := false
    for iter.Next(&key, &value) {
        if value == 1 {
            fmt.Printf("  - PID %d\n", key)
            found = true
        }
    }
    
    if !found {
        fmt.Println("  (none)")
    }
    
    return iter.Err()
}

func (sb *SignalBlocker) StartEventLoop() {
    fmt.Println("Starting signal monitoring...")
    fmt.Println("Events will be displayed as they occur:")
    fmt.Println("Format: [BLOCKED/ALLOWED] Signal SIG to PID target (from PID source)")
    fmt.Println()

    go func() {
        for {
            record, err := sb.reader.Read()
            if err != nil {
                log.Printf("Error reading from ring buffer: %v", err)
                continue
            }

            if len(record.RawSample) < int(unsafe.Sizeof(SignalEvent{})) {
                continue
            }

            var event SignalEvent
            buf := bytes.NewReader(record.RawSample)
            if err := binary.Read(buf, binary.LittleEndian, &event); err != nil {
                log.Printf("Error parsing event: %v", err)
                continue
            }

            status := "ALLOWED"
            if event.Blocked == 1 {
                status = "BLOCKED"
                timestamp := time.Unix(0, int64(event.Timestamp))
                fmt.Printf("[%s] %s Signal %d to PID %d (from PID %d)\n",
                    timestamp.Format("15:04:05"),
                    status,
                    event.Signal,
                    event.TargetPID,
                    event.SourcePID)
            }
        }
    }()
}

func printUsage() {
    fmt.Println("Usage:")
    fmt.Println("  block <pid>     - Block signals to specified PID")
    fmt.Println("  unblock <pid>   - Unblock signals to specified PID")  
    fmt.Println("  list            - List currently blocked PIDs")
    fmt.Println("  help            - Show this help")
    fmt.Println("  quit/exit       - Exit the program")
    fmt.Println()
}

func main() {
    fmt.Println("eBPF Signal Blocker")
    fmt.Println("===================")
    
    blocker, err := NewSignalBlocker()
    if err != nil {
        log.Fatalf("Failed to initialize signal blocker: %v", err)
    }
    defer blocker.Close()

    // Start event monitoring
    blocker.StartEventLoop()

    // Handle Ctrl+C gracefully
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\nShutting down...")
        blocker.Close()
        os.Exit(0)
    }()

    printUsage()

    // Interactive command loop
    for {
        fmt.Print("> ")
        var command string
        var arg string
        
        n, err := fmt.Scanf("%s %s", &command, &arg)
        if err != nil && n == 0 {
            continue
        }

        switch command {
        case "block":
            if arg == "" {
                fmt.Println("Error: PID required")
                continue
            }
            pid, err := strconv.ParseUint(arg, 10, 32)
            if err != nil {
                fmt.Printf("Error: Invalid PID '%s'\n", arg)
                continue
            }
            if err := blocker.BlockPID(uint32(pid)); err != nil {
                fmt.Printf("Error: %v\n", err)
            }

        case "unblock":
            if arg == "" {
                fmt.Println("Error: PID required")
                continue
            }
            pid, err := strconv.ParseUint(arg, 10, 32)
            if err != nil {
                fmt.Printf("Error: Invalid PID '%s'\n", arg)
                continue
            }
            if err := blocker.UnblockPID(uint32(pid)); err != nil {
                fmt.Printf("Error: %v\n", err)
            }

        case "list":
            if err := blocker.ListBlockedPIDs(); err != nil {
                fmt.Printf("Error: %v\n", err)
            }

        case "help":
            printUsage()

        case "quit", "exit":
            fmt.Println("Goodbye!")
            return

        default:
            fmt.Printf("Unknown command: %s\n", command)
            printUsage()
        }
    }
}