# sigwatch

An eBPF-based signal monitoring tool that captures system-wide signal events with detailed context.

## Overview

Signal Reader uses eBPF tracepoints to monitor signals in real-time across the entire system. It captures both `signal_generate` (when a signal is created) and `signal_deliver` (when a signal is delivered to a process) events, providing detailed diagnostic information including:

- Signal number and name (e.g., SIGSEGV, SIGTERM)
- Process ID and command name
- Signal context (errno, code, faulting address)
- Full userspace stack traces

## Requirements

- Linux kernel 5.10+
- `libbpf` library
- `bpftool`
- `clang` with BPF target support
- Optional: `addr2line` (part of binutils) for symbolization

## Building

```bash
make
```

The compiled binary will be located at `build/probe_read`.

## Usage

```bash
sudo ./build/probe_read [OPTIONS]
```

### Options

- `-w filename` - Write output to file instead of stdout
- `-f signum` - Watch for specific signal number (can be used multiple times)
- `-j` - Output in JSON format
- `-G` - Disable signal_generate events
- `-D` - Disable signal_deliver events
- `-h` - Show help message

### Examples

**Monitor only SIGSEGV (signal 11):**
```bash
sudo ./build/probe_read -f 11
```

**Monitor SIGSEGV and SIGABRT with JSON output:**
```bash
sudo ./build/probe_read -f 11 -f 6 -j
```

**Monitor only signal delivery events (not generation) and write output to a file:**
```bash
sudo ./build/probe_read -G -w sigdeliver.log
```

## Output Format

### Human-Readable Format

```
Signal 11 (SIGSEGV) delivered to process 12345 (test_program)
  Signal context:
    sig_code: 1 (SEGV_MAPERR - address not mapped)
    Faulting address: 0x0
    Instruction pointer: 0x5555d6a11f38
  Stack trace (5 frames):
    #0: 0x5555d6a11f38 crash_function at test.c:42 (in /usr/bin/test_program)
    #1: 0x5555d6a11e20 main at test.c:67 (in /usr/bin/test_program)
    #2: 0x7f8b2c829d90 __libc_start_call_main at libc-start.c:128 (in /lib/x86_64-linux-gnu/libc.so.6)
    #3: 0x7f8b2c829e40 __libc_start_main_impl at libc-start.c:379 (in /lib/x86_64-linux-gnu/libc.so.6)
    #4: 0x5555d6a11c85 _start+0x25 (in /usr/bin/test_program)
```

## Default Signals Monitored

When no `-f` option is specified, the following signals are monitored by default:

- SIGHUP (1)
- SIGINT (2)
- SIGQUIT (3)
- SIGABRT (6)
- SIGTERM (15)
- SIGUSR1 (10)
- SIGUSR2 (12)
- SIGCHLD (17)
- SIGCONT (18)
- SIGSTOP (19)
- SIGSEGV (11)
- SIGPIPE (13)

## Troubleshooting

**"Permission denied" when loading BPF program:**
- Ensure you're running with root privileges (`sudo`)

**Stack traces show `[unknown]`:**
- Binary may not have debug symbols (compile with `-g`)
- Binary may be stripped (use unstripped version)
- Address may be in a region not captured by VMAs
- Ensure `addr2line` is installed
