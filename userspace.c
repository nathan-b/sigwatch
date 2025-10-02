#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <probe.skel.h>
#include "probe.h"

static volatile bool running = false;

uint8_t sigmask[_NSIG] = {0};

// Command line options structure
struct options {
	FILE *output_file;
	const char *output_filename;
	bool json_mode;
	uint8_t filter_signals[64];
	bool has_filter;
	bool enable_generate;
	bool enable_deliver;
};

/***************************************************************
 ** Utility functions
 */

/**
 * Get human-readable signal name
 */
static const char* get_signal_name(int signum)
{
	switch (signum) {
		case SIGHUP: return "SIGHUP";
		case SIGINT: return "SIGINT";
		case SIGQUIT: return "SIGQUIT";
		case SIGILL: return "SIGILL";
		case SIGTRAP: return "SIGTRAP";
		case SIGABRT: return "SIGABRT";
		case SIGBUS: return "SIGBUS";
		case SIGFPE: return "SIGFPE";
		case SIGKILL: return "SIGKILL";
		case SIGUSR1: return "SIGUSR1";
		case SIGSEGV: return "SIGSEGV";
		case SIGUSR2: return "SIGUSR2";
		case SIGPIPE: return "SIGPIPE";
		case SIGALRM: return "SIGALRM";
		case SIGTERM: return "SIGTERM";
		case SIGCHLD: return "SIGCHLD";
		case SIGCONT: return "SIGCONT";
		case SIGSTOP: return "SIGSTOP";
		case SIGTSTP: return "SIGTSTP";
		case SIGTTIN: return "SIGTTIN";
		case SIGTTOU: return "SIGTTOU";
		case SIGURG: return "SIGURG";
		case SIGXCPU: return "SIGXCPU";
		case SIGXFSZ: return "SIGXFSZ";
		case SIGVTALRM: return "SIGVTALRM";
		case SIGPROF: return "SIGPROF";
		case SIGWINCH: return "SIGWINCH";
		case SIGIO: return "SIGIO";
		case SIGPWR: return "SIGPWR";
		case SIGSYS: return "SIGSYS";
		default: return NULL;
	}
}

/**
 * Sleep for the given number of milliseconds.
 *
 * @param milliseconds  Number of ms to sleep for
 */
static void msleep(uint32_t milliseconds)
{
	struct timespec ts = {
	    .tv_sec = milliseconds / 1000,
	    .tv_nsec = (milliseconds % 1000) * 1000000,
	};
	nanosleep(&ts, NULL);
}

/**
 * Helpful userspace function for printing output.
 */
static int bpf_print(enum libbpf_print_level level, const char* format, va_list args)
{
	if (level == LIBBPF_DEBUG)
	{
		return 0;
	}
	return vfprintf(stderr, format, args);
}

/**
 * Give the user a way to exit the program cleanly.
 */
static void sig_handler(int sig)
{
	switch (sig)
	{
	case SIGINT:
	case SIGTERM:
		running = false;
		break;
	}
}

/**
 * Escape a string for JSON output
 */
static void json_escape_string(FILE *f, const char *s)
{
	while (*s) {
		switch (*s) {
			case '"': fprintf(f, "\\\""); break;
			case '\\': fprintf(f, "\\\\"); break;
			case '\n': fprintf(f, "\\n"); break;
			case '\r': fprintf(f, "\\r"); break;
			case '\t': fprintf(f, "\\t"); break;
			default: fputc(*s, f); break;
		}
		s++;
	}
}

/**
 * Symbolize an address and store result in a buffer
 * Returns 1 if symbolized, 0 otherwise
 */
static int symbolize_address_to_buffer(struct vma_info *vmas, int vma_count, __u64 addr,
                                        char *symbol_buf, size_t symbol_size,
                                        char *file_buf, size_t file_size)
{
	for (int i = 0; i < vma_count; i++) {
		struct vma_info *vma = &vmas[i];

		if (addr >= vma->start && addr < vma->end) {
			// Found the mapping
			if (vma->path[0] == '/' || vma->path[0] != '\0') {
				// Calculate file offset
				__u64 file_offset = (addr - vma->start) + vma->offset;

				// Try to symbolize with addr2line
				char cmd[512];
				snprintf(cmd, sizeof(cmd), "addr2line -e %s -f -i -p 0x%llx 2>/dev/null",
				         vma->path, file_offset);

				FILE *pipe = popen(cmd, "r");
				if (pipe) {
					char result[256];
					if (fgets(result, sizeof(result), pipe)) {
						// Remove newline
						result[strcspn(result, "\n")] = 0;
						if (strncmp(result, "??", 2) != 0) {
							snprintf(symbol_buf, symbol_size, "%s", result);
							snprintf(file_buf, file_size, "%s", vma->path);
							pclose(pipe);
							return 1;
						}
					}
					pclose(pipe);
				}

				// Couldn't symbolize, but we have the file
				snprintf(symbol_buf, symbol_size, "%s+0x%llx", vma->path, file_offset);
				snprintf(file_buf, file_size, "%s", vma->path);
			} else {
				// Anonymous or special mapping
				unsigned int r = (vma->flags >> 0) & 1;
				unsigned int w = (vma->flags >> 1) & 1;
				unsigned int x = (vma->flags >> 2) & 1;
				snprintf(symbol_buf, symbol_size, "[%c%c%c]", r ? 'r' : '-', w ? 'w' : '-', x ? 'x' : '-');
				file_buf[0] = '\0';
			}
			return 1;
		}
	}

	return 0;
}

/**
 * Print a stack trace from the provided addresses
 */
static void print_stack_trace(struct options *opts, int depth, __u64 *stack, struct vma_info *vmas, int vma_count, __u64 base_addr)
{
	FILE *out = opts->output_file ? opts->output_file : stdout;

	if (opts->json_mode) {
		fprintf(out, "\"stack\":[");
		for (int i = 0; i < depth; i++) {
			__u64 runtime_addr = stack[i];
			char symbol_buf[512] = "";
			char file_buf[256] = "";

			if (i > 0) fprintf(out, ",");
			fprintf(out, "{\"frame\":%d,\"address\":\"0x%llx\"", i, (unsigned long long)runtime_addr);

			if (symbolize_address_to_buffer(vmas, vma_count, runtime_addr, symbol_buf, sizeof(symbol_buf), file_buf, sizeof(file_buf))) {
				fprintf(out, ",\"symbol\":\"");
				json_escape_string(out, symbol_buf);
				fprintf(out, "\"");
				if (file_buf[0]) {
					fprintf(out, ",\"file\":\"");
					json_escape_string(out, file_buf);
					fprintf(out, "\"");
				}
			} else {
				// Check if this address is plausibly in the main executable
				if (runtime_addr >= base_addr && runtime_addr < base_addr + 0x6400000) {
					__u64 file_offset = runtime_addr - base_addr;
					fprintf(out, ",\"offset\":\"0x%llx\"", (unsigned long long)file_offset);
				} else {
					fprintf(out, ",\"symbol\":\"[unknown]\"");
				}
			}
			fprintf(out, "}");
		}
		fprintf(out, "]");
	} else {
		if (depth == 0) {
			fprintf(out, "  No stack trace available\n");
			return;
		}

		fprintf(out, "  Stack trace (%d frames):\n", depth);
		for (int i = 0; i < depth; i++) {
			__u64 runtime_addr = stack[i];
			char symbol_buf[512] = "";
			char file_buf[256] = "";

			fprintf(out, "    #%d: 0x%llx ", i, (unsigned long long)runtime_addr);

			if (symbolize_address_to_buffer(vmas, vma_count, runtime_addr, symbol_buf, sizeof(symbol_buf), file_buf, sizeof(file_buf))) {
				fprintf(out, "%s", symbol_buf);
				if (file_buf[0]) {
					fprintf(out, " (in %s)", file_buf);
				}
				fprintf(out, "\n");
			} else {
				// Check if this address is plausibly in the main executable
				// (base_addr to base_addr + reasonable executable size, e.g., 100MB)
				if (runtime_addr >= base_addr && runtime_addr < base_addr + 0x6400000) {
					__u64 file_offset = runtime_addr - base_addr;
					fprintf(out, "(main+0x%llx)\n", (unsigned long long)file_offset);
				} else {
					fprintf(out, "[unknown]\n");
				}
			}
		}
	}
}

/**
 * Ring buffer event handler.
 * Handles signal events.
 */
static int handle_event(void* ctx, void* evtp, size_t size)
{
	struct options *opts = (struct options *)ctx;
	static pid_t my_pid = 0;
	if (my_pid == 0) {
		my_pid = getpid();
	}

	struct signal_evt* evt = evtp;
	if (size < sizeof(*evt))
	{
		fprintf(stderr, "Event size too small: %zu\n", size);
		return 0;
	}
	if (evt->signum < 0 || evt->signum >= _NSIG)
	{
		fprintf(stderr, "Invalid signal number: %d\n", evt->signum);
		return 0;
	}

	// Filter out signals from our own process and children (addr2line, etc.)
	if (evt->task.pid == my_pid || getpgid(evt->task.pid) == my_pid)
	{
		return 0;
	}

	if (sigmask[evt->signum])
	{
		FILE *out = opts->output_file ? opts->output_file : stdout;
		const char *sig_name = get_signal_name(evt->signum);

		if (opts->json_mode) {
			fprintf(out, "{\"signal\":%d", evt->signum);
			if (sig_name) {
				fprintf(out, ",\"signal_name\":\"%s\"", sig_name);
			}
			fprintf(out, ",\"event_type\":\"%s\",\"pid\":%d,\"comm\":\"",
			        evt->evt_type == SIG_GENERATE ? "generate" : "deliver",
			        evt->task.pid);
			json_escape_string(out, evt->task.comm);
			fprintf(out, "\",\"sig_code\":%d", evt->sig_code);

			if (evt->fault_addr != 0) {
				fprintf(out, ",\"fault_addr\":\"0x%llx\"", (unsigned long long)evt->fault_addr);
			}
			if (evt->ip != 0) {
				fprintf(out, ",\"ip\":\"0x%llx\"", (unsigned long long)evt->ip);
			}
			fprintf(out, ",");
			print_stack_trace(opts, evt->stack_depth, evt->stack, evt->vmas, evt->vma_count, evt->base_addr);
			fprintf(out, "}\n");
			fflush(out);
		} else {
			fprintf(out, "Signal %d", evt->signum);
			if (sig_name) {
				fprintf(out, " (%s)", sig_name);
			}
			fprintf(out, " ");
			if (evt->evt_type == SIG_GENERATE) {
				fprintf(out, "generated by process ");
			} else if (evt->evt_type == SIG_DELIVER) {
				fprintf(out, "delivered to process ");
			} else {
				fprintf(out, "with unknown event type %d for process ", evt->evt_type);
			}
			fprintf(out, "%d (%s)\n", evt->task.pid, evt->task.comm);

			// Print signal context
			fprintf(out, "  Signal context:\n");
			fprintf(out, "    sig_code: %d ", evt->sig_code);

			// Decode sig_code based on signal type
			if (evt->signum == SIGSEGV) {
				switch (evt->sig_code) {
					case 1: fprintf(out, "(SEGV_MAPERR - address not mapped)\n"); break;
					case 2: fprintf(out, "(SEGV_ACCERR - invalid permissions)\n"); break;
					default: fprintf(out, "(unknown)\n"); break;
				}
			} else if (evt->signum == SIGBUS) {
				switch (evt->sig_code) {
					case 1: fprintf(out, "(BUS_ADRALN - invalid address alignment)\n"); break;
					case 2: fprintf(out, "(BUS_ADRERR - non-existent physical address)\n"); break;
					case 3: fprintf(out, "(BUS_OBJERR - object specific hardware error)\n"); break;
					default: fprintf(out, "(unknown)\n"); break;
				}
			} else if (evt->signum == SIGILL) {
				switch (evt->sig_code) {
					case 1: fprintf(out, "(ILL_ILLOPC - illegal opcode)\n"); break;
					case 2: fprintf(out, "(ILL_ILLOPN - illegal operand)\n"); break;
					case 3: fprintf(out, "(ILL_ILLADR - illegal addressing mode)\n"); break;
					case 4: fprintf(out, "(ILL_ILLTRP - illegal trap)\n"); break;
					case 5: fprintf(out, "(ILL_PRVOPC - privileged opcode)\n"); break;
					case 6: fprintf(out, "(ILL_PRVREG - privileged register)\n"); break;
					case 7: fprintf(out, "(ILL_COPROC - coprocessor error)\n"); break;
					case 8: fprintf(out, "(ILL_BADSTK - internal stack error)\n"); break;
					default: fprintf(out, "(unknown)\n"); break;
				}
			} else {
				fprintf(out, "\n");
			}

			if (evt->fault_addr != 0) {
				fprintf(out, "    Faulting address: 0x%llx\n", (unsigned long long)evt->fault_addr);
			}
			if (evt->ip != 0) {
				fprintf(out, "    Instruction pointer: 0x%llx\n", (unsigned long long)evt->ip);
			}

			print_stack_trace(opts, evt->stack_depth, evt->stack, evt->vmas, evt->vma_count, evt->base_addr);
			fprintf(out, "\n");
		}
	}
	return 0;
}

/**
 * Parse command line options and populate options struct
 * Returns 0 on success, -1 on error, 1 if help was requested
 */
static int parse_options(int argc, char **argv, struct options *opts)
{
	int opt;

	// Initialize options with defaults
	opts->output_file = NULL;
	opts->output_filename = NULL;
	opts->json_mode = false;
	opts->has_filter = false;
	opts->enable_generate = true;
	opts->enable_deliver = true;
	memset(opts->filter_signals, 0, sizeof(opts->filter_signals));

	// Parse command line arguments
	while ((opt = getopt(argc, argv, "w:f:jGDh")) != -1) {
		switch (opt) {
			case 'w':
				opts->output_filename = optarg;
				break;
			case 'f':
				{
					int signum = atoi(optarg);
					if (signum < 0 || signum >= 64) {
						fprintf(stderr, "Invalid signal number: %d (must be 0-63)\n", signum);
						return -1;
					}
					opts->filter_signals[signum] = 1;
					opts->has_filter = true;
				}
				break;
			case 'j':
				opts->json_mode = true;
				break;
			case 'G':
				opts->enable_generate = false;
				break;
			case 'D':
				opts->enable_deliver = false;
				break;
			case 'h':
			default:
				fprintf(stderr, "Usage: %s [-w filename] [-f signum] [-j] [-G] [-D] [-h]\n", argv[0]);
				fprintf(stderr, "  -w filename  Write output to file instead of stdout\n");
				fprintf(stderr, "  -f signum    Watch specific signal (can be used multiple times)\n");
				fprintf(stderr, "  -j           Output in JSON format\n");
				fprintf(stderr, "  -G           Disable signal_generate events\n");
				fprintf(stderr, "  -D           Disable signal_deliver events\n");
				fprintf(stderr, "  -h           Show this help\n");
				return opt == 'h' ? 1 : -1;
		}
	}

	// Open output file if specified
	if (opts->output_filename) {
		opts->output_file = fopen(opts->output_filename, "w");
		if (!opts->output_file) {
			fprintf(stderr, "Failed to open output file %s: %s\n",
			        opts->output_filename, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/**
 * Helper macro to load and attach a BPF program
 */
#define load_bpf_prog(_probe, _name)                                               \
	do                                                                             \
	{                                                                              \
		int filler_err = 0;                                                        \
		(_probe)->links._name = bpf_program__attach((_probe)->progs._name);        \
		filler_err = libbpf_get_error((_probe)->links._name);                      \
		if (filler_err != 0)                                                       \
		{                                                                          \
			fprintf(stderr, "Could not load filler " #_name ": %d\n", filler_err); \
			goto cleanup;                                                          \
		}                                                                          \
	} while (0)

int main(int argc, char** argv)
{
	struct ring_buffer* ringbuf = NULL;
	struct probe* probe;
	struct options opts;
	int err = 0;

	// Parse command line options
	err = parse_options(argc, argv, &opts);
	if (err != 0) {
		return err < 0 ? 1 : 0;  // -1 is error (return 1), 1 is help (return 0)
	}

	// If user provided -f options, only enable those signals
	// Otherwise, use default set
	if (opts.has_filter) {
		for (int i = 0; i < _NSIG; i++) {
			sigmask[i] = (i < 64) ? opts.filter_signals[i] : 0;
		}
	} else {
		// Default signals we care about
		sigmask[SIGHUP] = 1;
		sigmask[SIGINT] = 1;
		sigmask[SIGQUIT] = 1;
		sigmask[SIGTERM] = 1;
		sigmask[SIGUSR1] = 1;
		sigmask[SIGUSR2] = 1;
		sigmask[SIGCHLD] = 1;
		sigmask[SIGCONT] = 1;
		sigmask[SIGSTOP] = 1;
		sigmask[SIGSEGV] = 1;
		sigmask[SIGPIPE] = 1;
		sigmask[SIGABRT] = 1;

		// Copy to opts.filter_signals for BPF map
		for (int i = 0; i < 64; i++) {
			opts.filter_signals[i] = (i < _NSIG) ? sigmask[i] : 0;
		}
	}

	// Set up libbpf console printer
	libbpf_set_print(bpf_print);

	// Remove memory limit (for bpf maps)
	struct rlimit rlim_new = {
	    .rlim_cur = RLIM_INFINITY,
	    .rlim_max = RLIM_INFINITY,
	};
	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new) != 0)
	{
		fprintf(stderr, "Fatal error: Could not increase memory limit.\n");
		return -1;
	}

	// Make sure we can clean up when user hits ^C
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Now open the eBPF program using the autogenerated libbpf skeleton
	probe = probe__open();
	if (!probe)
	{
		fprintf(stderr, "Failed to load eBPF probe.\n");
		return -1;
	}

	// Load and verify eBPF program
	err = probe__load(probe);
	if (err != 0)
	{
		fprintf(stderr, "Could not load (and verify) eBPF program: %d\n", err);
		goto cleanup;
	}

	// Attach the event handler to the probe's ring buffer
	ringbuf = ring_buffer__new(bpf_map__fd(probe->maps.ringbuf), handle_event, &opts, NULL);
	if (!ringbuf)
	{
		err = -1;
		fprintf(stderr, "Could not create ring buffer\n");
		goto cleanup;
	}

	// Populate signal filter map
	int filter_fd = bpf_map__fd(probe->maps.signal_filter);
	for (__u32 i = 0; i < 64; i++) {
		err = bpf_map_update_elem(filter_fd, &i, &opts.filter_signals[i], BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Could not update signal_filter for signal %d: %d\n", i, err);
			goto cleanup;
		}
	}

	// Load tracepoints based on user preferences
	if (opts.enable_generate) {
		load_bpf_prog(probe, bpf_signal_generate);
	}
	if (opts.enable_deliver) {
		load_bpf_prog(probe, bpf_signal_deliver);
	}

	// Make sure at least one tracepoint is enabled
	if (!opts.enable_generate && !opts.enable_deliver) {
		fprintf(stderr, "Error: Both -G and -D specified. At least one tracepoint must be enabled.\n");
		goto cleanup;
	}

	// Event processing loop
	running = true;
	while (running)
	{
		const int timeout_ms = 100;

		err = ring_buffer__poll(ringbuf, timeout_ms);
		if (err == -EINTR)
		{
			err = 0;
			running = false;
		}
		else if (err < 0)
		{
			fprintf(stderr, "Ring buffer poll error: %d\n", err);
			running = false;
		}

		msleep(1);
	}

cleanup:

	if (ringbuf)
	{
		ring_buffer__free(ringbuf);
	}
	probe__destroy(probe);

	if (opts.output_file)
	{
		fclose(opts.output_file);
	}

	return err;
}
