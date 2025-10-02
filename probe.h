#pragma once

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 24
#define MAX_VMAS 64
#define MAX_PATH_LEN 128

struct vma_info
{
	__u64 start;
	__u64 end;
	__u64 offset;
	__u32 flags;
	char path[MAX_PATH_LEN];
};

struct signal_evt
{
	enum {
		SIG_GENERATE,
		SIG_DELIVER,
	} evt_type;
	int signum;
	struct {
		char comm[TASK_COMM_LEN];
		pid_t pid;
	} task;
	// Signal context
	int sig_errno;
	int sig_code;
	__u64 fault_addr;  // Faulting address for SIGSEGV/SIGBUS
	__u64 ip;          // Instruction pointer
	__u64 base_addr;
	int stack_depth;
	__u64 stack[MAX_STACK_DEPTH];
	int vma_count;
	struct vma_info vmas[MAX_VMAS];
};
