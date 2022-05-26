#include "arguments.h"
#include "goroutines.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SIZE 100

struct function_input {
    char strParam[MAX_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// This instrumentation attaches uprobe to the following function:
// func main.worker(str string)
SEC("uprobe/main_worker")
int uprobe_Main_Worker(struct pt_regs *ctx) {
    struct function_input funcInput = {};

    void* param_ptr = 0;
    bpf_probe_read(&param_ptr, sizeof(param_ptr), (void *)(ctx->rsp+8));

    // Replace
    char replace[17] = "ebpf header value";
    long success = bpf_probe_write_user(param_ptr, replace, sizeof(replace));
    bpf_printk("** RESULT %d", success);
    return 0;
}