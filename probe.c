#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "probe.h"
#include "maps.h"

char LICENSE[] SEC("license") = "GPL";



////////////////////////////////////////////////////////////////
// Helpers

static __always_inline void* bpf_syscall_get_argument_from_ctx(const void* ctx,
                                                               int idx)
{
    if (!ctx) return NULL;
	unsigned long arg;
	struct pt_regs* regs = *((struct pt_regs**)ctx);

	switch (idx) {
	case 0:
        bpf_core_read(&arg, sizeof(arg), &regs->di);
		break;
	case 1:
        bpf_core_read(&arg, sizeof(arg), &regs->si);
		break;
	case 2:
        bpf_core_read(&arg, sizeof(arg), &regs->dx);
		break;
	case 3:
        bpf_core_read(&arg, sizeof(arg), &regs->r10);
		break;
	case 4:
        bpf_core_read(&arg, sizeof(arg), &regs->r8);
		break;
	case 5:
        bpf_core_read(&arg, sizeof(arg), &regs->r9);
		break;
	default:
		arg = 0;
	}

	return (void*)arg;
}

static __always_inline __u64 get_base_addr(void)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }

    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (!mm) {
        return 0;
    }

    __u64 start_code;
    bpf_probe_read_kernel(&start_code, sizeof(start_code), &mm->start_code);
    return start_code;
}


// Structure to pass data to VMA callback
struct vma_capture_ctx {
    struct vma_info *vmas;
    int max_vmas;
    int count;
    __u64 *addresses;
    int num_addresses;
};

// Callback for bpf_find_vma - called for each VMA containing our addresses
static long vma_callback(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
    struct vma_capture_ctx *ctx = data;

    int idx = ctx->count;

    // Bounds check for verifier
    if (idx < 0 || idx >= ctx->max_vmas || idx >= MAX_VMAS) {
        return 1; // Stop iteration
    }

    struct vma_info *v = &ctx->vmas[idx];

    // Read VMA start and end addresses
    v->start = BPF_CORE_READ(vma, vm_start);
    v->end = BPF_CORE_READ(vma, vm_end);

    // Read VMA flags
    v->flags = (__u32)BPF_CORE_READ(vma, vm_flags);

    // Read page offset
    v->offset = BPF_CORE_READ(vma, vm_pgoff) << 12; // Convert pages to bytes

    // Try to read the file path
    struct file *vm_file = BPF_CORE_READ(vma, vm_file);
    if (vm_file) {
        struct dentry *dentry = BPF_CORE_READ(vm_file, f_path.dentry);
        if (dentry) {
            struct qstr d_name = BPF_CORE_READ(dentry, d_name);
            bpf_probe_read_kernel_str(v->path, MAX_PATH_LEN, d_name.name);
        } else {
            v->path[0] = '\0';
        }
    } else {
        v->path[0] = '\0';
    }

    ctx->count++;
    return 0; // Continue iteration
}

static __always_inline int capture_vmas_for_addresses(struct vma_info *vmas, int max_vmas,
                                                      __u64 *addresses, int num_addresses)
{
    struct vma_capture_ctx ctx = {
        .vmas = vmas,
        .max_vmas = max_vmas,
        .count = 0,
        .addresses = addresses,
        .num_addresses = num_addresses,
    };

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }

    // Bounds check for verifier
    if (num_addresses > MAX_STACK_DEPTH) {
        num_addresses = MAX_STACK_DEPTH;
    }

    // Use bpf_find_vma for each stack address
    #pragma unroll
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        if (i >= num_addresses) {
            break;
        }

        if (ctx.count >= max_vmas || ctx.count >= MAX_VMAS) {
            break;
        }

        // Find VMA containing this address
        long ret = bpf_find_vma(task, addresses[i], vma_callback, &ctx, 0);
        if (ret < 0) {
            // VMA not found or error
            continue;
        }
    }

    return ctx.count;
}

static __always_inline int capture_user_stack(void *ctx, __u64 *stack, __u32 stack_size)
{
    long stack_ret = bpf_get_stack(ctx, stack, stack_size, BPF_F_USER_STACK);
    if (stack_ret < 0) {
        bpf_printk("bpf_get_stack failed with error code: %ld\n", stack_ret);
        return 0;
    } else if (stack_ret == 0) {
        // See if we can get a more useful stack from the task struct
        struct task_struct *task = bpf_get_current_task_btf();
        if (!task) {
            // We tried our best
            return 0;
        }
        stack_ret = bpf_get_task_stack(task, stack, stack_size, BPF_F_USER_STACK);
        if (stack_ret < 0) {
            bpf_printk("bpf_get_task_stack failed with error code: %ld\n", stack_ret);
            return 0;
        } else {
            return stack_ret / sizeof(__u64);
        }
    } else {
        return stack_ret / sizeof(__u64);
    }
}

////////////////////////////////////////////////////////////////
// Common handler logic (shared inline function)

static __always_inline int handle_signal_common(void *ctx, struct signal_evt *ev)
{
    // Capture base address for PIE executable support
    ev->base_addr = get_base_addr();

    // Capture stack trace first
    ev->stack_depth = capture_user_stack(ctx, ev->stack, sizeof(ev->stack));

    // IP is the first address in the stack trace
    ev->ip = (ev->stack_depth > 0) ? ev->stack[0] : 0;

    // Capture memory mappings for stack addresses
    ev->vma_count = capture_vmas_for_addresses(ev->vmas, MAX_VMAS, ev->stack, ev->stack_depth);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

////////////////////////////////////////////////////////////////
// Tracepoints

SEC("tracepoint/signal/signal_generate")
int bpf_signal_generate(struct trace_event_raw_signal_generate *ctx)
{
    struct signal_evt *ev;

    // Check signal filter
    __u32 sig = ctx->sig;
    if (sig < 64) {
        __u8 *enabled = bpf_map_lookup_elem(&signal_filter, &sig);
        if (!enabled || *enabled == 0) {
            return 0; // Signal not in filter
        }
    }

    // Filter out addr2line and other common tools early
    char comm_buf[16];
    bpf_probe_read_kernel_str(comm_buf, sizeof(comm_buf), ctx->comm);

    // Skip common child processes that generate noise
    if (comm_buf[0] == 'a' && comm_buf[1] == 'd' && comm_buf[2] == 'd' && comm_buf[3] == 'r') {
        return 0; // Skip addr2line
    }
    if (comm_buf[0] == 's' && comm_buf[1] == 'h') {
        return 0; // Skip sh
    }

    ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        return 0; // buffer full, drop
    }

    ev->evt_type = SIG_GENERATE;
    ev->signum   = ctx->sig;
    ev->task.pid = ctx->pid;
    __builtin_memcpy(ev->task.comm, comm_buf, sizeof(ev->task.comm));

    // Capture signal context
    ev->sig_errno = ctx->errno;
    ev->sig_code = ctx->code;
    ev->fault_addr = 0;  // Not directly available in signal_generate

    // Call common handler
    return handle_signal_common(ctx, ev);
}

SEC("tracepoint/signal/signal_deliver")
int bpf_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
    struct signal_evt *ev;

    // Check signal filter
    __u32 sig = ctx->sig;
    if (sig < 64) {
        __u8 *enabled = bpf_map_lookup_elem(&signal_filter, &sig);
        if (!enabled || *enabled == 0) {
            return 0; // Signal not in filter
        }
    }

    // Filter out addr2line and other common tools early
    char comm_buf[16];
    bpf_get_current_comm(comm_buf, sizeof(comm_buf));

    // Skip common child processes that generate noise
    if (comm_buf[0] == 'a' && comm_buf[1] == 'd' && comm_buf[2] == 'd' && comm_buf[3] == 'r') {
        return 0; // Skip addr2line
    }
    if (comm_buf[0] == 's' && comm_buf[1] == 'h') {
        return 0; // Skip sh
    }

    ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        return 0; // buffer full, drop
    }

    ev->evt_type = SIG_DELIVER;
    ev->signum   = ctx->sig;
    ev->task.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(ev->task.comm, comm_buf, sizeof(ev->task.comm));

    // Capture signal context
    ev->sig_errno = ctx->errno;
    ev->sig_code = ctx->code;
    ev->fault_addr = 0;  // Not directly available in signal_deliver

    // Call common handler
    return handle_signal_common(ctx, ev);
}

