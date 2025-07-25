#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "usdt.bpf.h"

#define MAX_FUNCTION_NAME 64
#define MAX_FILENAME 128
#define MAX_FUNCTION_COUNT 10
#define MAX_PROCESS_NUM 512
#define MAX_ARG_SIZE 256

typedef struct {
    char filename[MAX_FILENAME];
    char function_name[MAX_FUNCTION_NAME];
    int line_no;
} Function_entry;

typedef struct {
    Function_entry call_stack[MAX_FUNCTION_COUNT];
    int count;
} Map;

// HashMap for function call stacks
// HashMap< ProcessID, Map[ call_stack[ filename, function_name, line_no ], count ] >
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, Map);
    __uint(max_entries, MAX_PROCESS_NUM);
} usdt_map SEC(".maps");

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_function_info {
    u32 pid;
    char function_name[MAX_FUNCTION_NAME];
    char filename[MAX_FILENAME];
    int line_no;
    int syscall_id;
    char arg0[MAX_ARG_SIZE];
    char arg1[MAX_ARG_SIZE];
};

// Keep this for temporary storage
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, Map);
    __uint(max_entries, 1);
} temp_map_storage SEC(".maps");

// Helper function to copy string manually
static __always_inline void copy_string(char *dst, const char *src, int max_len) {
    #pragma unroll
    for (int i = 0; i < max_len - 1; i++) {
        dst[i] = src[i];
        if (src[i] == '\0') break;
    }
    dst[max_len - 1] = '\0';
}

static __always_inline pid_t get_parent_pid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;

    struct task_struct *parent;
    if (bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent) != 0) {
        return 0;
    }
    
    pid_t parent_pid;
    if (bpf_probe_read_kernel(&parent_pid, sizeof(parent_pid), &parent->pid) != 0) {
        return 0;
    }
    
    return parent_pid;
}

// Helper function to convert integer to string
static __always_inline void int_to_string(long num, char *str, int max_len) {
    if (max_len < 2) return;
    
    if (num == 0) {
        str[0] = '0';
        str[1] = '\0';
        return;
    }
    
    int i = 0;
    int is_negative = 0;
    
    if (num < 0) {
        is_negative = 1;
        num = -num;
    }
    
    // Convert digits in reverse order
    char temp[32];
    while (num > 0 && i < 31) {
        temp[i++] = '0' + (num % 10);
        num /= 10;
    }
    
    int j = 0;
    if (is_negative && j < max_len - 1) {
        str[j++] = '-';
    }
    
    // Copy digits in correct order
    while (i > 0 && j < max_len - 1) {
        str[j++] = temp[--i];
    }
    str[j] = '\0';
}

// Fixed handle_syscalls function that returns success/failure
static __always_inline int handle_syscalls(int syscall_nr, struct event_function_info *event) {
    if (!event) {
        return -1;
    }

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    Map *map = bpf_map_lookup_elem(&usdt_map, &pid);

    // if that process is not a PHP process, skip it
    if (!map || map->count <= 0 || map->count > MAX_FUNCTION_COUNT) {
        bpf_printk("No PHP stack found for PID=%d", pid);
        return -1;
    }

    event->pid = pid;
    event->syscall_id = syscall_nr;

    // Clear arguments
    event->arg0[0] = '\0';
    event->arg1[0] = '\0';

    // Safe array access with proper bounds checking
    int last_index = map->count - 1;
    if (last_index >= 0 && last_index < MAX_FUNCTION_COUNT) {
        Function_entry *last_func = &map->call_stack[last_index];
        copy_string(event->function_name, last_func->function_name, MAX_FUNCTION_NAME);
        copy_string(event->filename, last_func->filename, MAX_FILENAME);
        event->line_no = last_func->line_no;
    } else {
        copy_string(event->function_name, "UNKNOWN", MAX_FUNCTION_NAME);
        copy_string(event->filename, "UNKNOWN", MAX_FILENAME);
        event->line_no = 0;
    }
    
    bpf_printk("SYSCALL %d: Process %d last called: %s() [%s:%d]", 
               syscall_nr, event->pid, event->function_name, event->filename, event->line_no);
    
    return 0;
}

static __always_inline int parse_arguments(struct trace_event_raw_sys_enter *ctx, struct event_function_info *event) {
    if (!event) {
        return -1; // Invalid event pointer
    }

    // Clear arguments
    event->arg0[0] = '\0';
    event->arg1[0] = '\0';

    // Read syscall arguments based on syscall number
    switch (ctx->id) {
        // arg0: fd
        case 0: // read
        case 1: // write
        case 91: // fchmod
            if (ctx->args[0]) {
                int fd = (int)ctx->args[0];
                
                // Just store the fd number as string - userspace will resolve it
                int_to_string(fd, event->arg0, MAX_ARG_SIZE);
            }
            else {
                event->arg0[0] = '\0';
                bpf_printk("fd: NULL");
            }
            break;
        // arg0: oldpathname, arg1: newpathname
        case 82: // rename
            if (ctx->args[0] && ctx->args[1]) {
                if (bpf_probe_read_user_str(event->arg0, MAX_ARG_SIZE, (char *)ctx->args[0]) < 0 || bpf_probe_read_user_str(event->arg1, MAX_ARG_SIZE, (char *)ctx->args[1]) < 0) {
                    bpf_printk("pathname read failed");
                }
                bpf_printk("oldpathname: %s, newpathname: %s", event->arg0, event->arg1);
            }
            else {
                event->arg0[0] = '\0';
                event->arg1[0] = '\0';
                bpf_printk("pathname: NULL");
            }
            break;
        // arg0: pathname
        case 2: // open
        case 4: // stat
        case 83: // mkdir
        case 90: // chmod
        case 258: // mkdirat
            if (ctx->args[0]) {
                if (bpf_probe_read_user_str(event->arg0, MAX_ARG_SIZE, (char *)ctx->args[0]) < 0) {
                    bpf_printk("pathname read failed");
                }
                bpf_printk("pathname: %s", event->arg0);
            }
            else {
                event->arg0[0] = '\0';
                bpf_printk("pathname: NULL");
            }
            break;
        // arg0: dirfd, arg1: pathname
        case 257: // openat
        case 262: // newfstatat
        case 263: // unlinkat
        case 268: // fchmodat
        case 437: // openat2
            if (ctx->args[0] && ctx->args[1]) {
                int dirfd = (int)ctx->args[0];
                if (bpf_probe_read_user_str(event->arg1, MAX_ARG_SIZE, (char *)ctx->args[1]) < 0) {
                    bpf_printk("pathname read failed");
                }
                int_to_string(dirfd, event->arg0, MAX_ARG_SIZE);
                bpf_printk("dirfd: %s, pathname: %s", event->arg0, event->arg1);
            }
            else {
                event->arg0[0] = '\0';
                event->arg1[0] = '\0';
                bpf_printk("dirfd and pathname: NULL");
            }
            break;
        default:
            bpf_printk("Unsupported syscall %d", ctx->id);
            return -2; // Unsupported syscall
    }

    return 0;
}

static __always_inline int func_caller(struct trace_event_raw_sys_enter *ctx) {
    struct event_function_info *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_printk("Failed to reserve ring buffer space");
        return 0;
    }

    if (handle_syscalls(ctx->id, event) != 0) {
        // Failed to find PHP stack, discard the event
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    if (parse_arguments(ctx, event) != 0) {
        bpf_ringbuf_discard(event, 0);
        bpf_printk("Failed to parse arguments for syscall %d", ctx->id);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int trace_newfstatat(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
    func_caller(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    pid_t current_pid = bpf_get_current_pid_tgid() >> 32;

    Map *map = NULL;
    pid_t source_id = 0;

    map = bpf_map_lookup_elem(&usdt_map, &current_pid);
    if (map && map->count > 0) {
        source_id = current_pid;
        goto send_event;
    }

    pid_t parent_pid = get_parent_pid();
    if (parent_pid > 0) {
        map = bpf_map_lookup_elem(&usdt_map, &parent_pid);
        if (map && map->count > 0) {
            goto send_event;
        }
    }

    bpf_printk("EXECVE: No PHP stack found for PID=%d", current_pid);
    return 0;

send_event:
    if (map && map->count > 0 && map->count <= MAX_FUNCTION_COUNT) {
        struct event_function_info *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (!event) {
            bpf_printk("EXECVE: Failed to reserve ring buffer space");
            return 0;
        }

        event->pid = current_pid;
        event->syscall_id = ctx->id;
        event->arg0[0] = '\0';
        event->arg1[0] = '\0';
        
        int last_index = map->count - 1;
        if (last_index >= 0 && last_index < MAX_FUNCTION_COUNT) {
            Function_entry *last_func = &map->call_stack[last_index];
            copy_string(event->function_name, last_func->function_name, MAX_FUNCTION_NAME);
            copy_string(event->filename, last_func->filename, MAX_FILENAME);
            event->line_no = last_func->line_no;
        } else {
            copy_string(event->function_name, "unknown", MAX_FUNCTION_NAME);
            copy_string(event->filename, "unknown", MAX_FILENAME);
            event->line_no = 0;
        }
        
        bpf_printk("EXECVE: Process %d last called: %s() [%s:%d]", 
                   event->pid, event->function_name, event->filename, event->line_no);
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

SEC("usdt")
int BPF_USDT(trace_php_function_entry, void *arg0, void *arg1, void *arg2)
{
    pid_t process_id = bpf_get_current_pid_tgid() >> 32;

    // Use small stack variables for reading
    char func_name[MAX_FUNCTION_NAME] = {};
    char file_name[MAX_FILENAME] = {};

    // Read function name from user space
    if (arg0) { 
        bpf_probe_read_user_str(func_name, MAX_FUNCTION_NAME, arg0);
    }
    
    // Read filename from user space
    if (arg1) {
        bpf_probe_read_user_str(file_name, MAX_FILENAME, arg1);
    }
    
    // Get line number
    int line_number = arg2 ? (int)(long)arg2 : 0;

    // Output to kernel
    bpf_printk("PHP[%d] -> %s() [%s:%d]", process_id, func_name, file_name, line_number);

    Map *map = bpf_map_lookup_elem(&usdt_map, &process_id);
    if (map) {
        // Bounds check before accessing
        if (map->count >= 0 && map->count < MAX_FUNCTION_COUNT) {
            // Copy data directly to the map entry
            Function_entry *entry = &map->call_stack[map->count];
            copy_string(entry->function_name, func_name, MAX_FUNCTION_NAME);
            copy_string(entry->filename, file_name, MAX_FILENAME);
            entry->line_no = line_number;
            map->count++;
        } else if (map->count >= MAX_FUNCTION_COUNT) {
            // Stack is full, replace the last entry (LIFO behavior)
            Function_entry *entry = &map->call_stack[MAX_FUNCTION_COUNT - 1];
            copy_string(entry->function_name, func_name, MAX_FUNCTION_NAME);
            copy_string(entry->filename, file_name, MAX_FILENAME);
            entry->line_no = line_number;
            bpf_printk("Call stack full for process %d - replaced last entry", process_id);
        }
    } else {
        // Use per-CPU array to avoid stack overflow
        u32 key = 0;
        Map *temp_map = bpf_map_lookup_elem(&temp_map_storage, &key);
        if (temp_map) {
            // Initialize the temporary map
            temp_map->count = 1;
            
            // Set first entry
            copy_string(temp_map->call_stack[0].function_name, func_name, MAX_FUNCTION_NAME);
            copy_string(temp_map->call_stack[0].filename, file_name, MAX_FILENAME);
            temp_map->call_stack[0].line_no = line_number;
            
            // Update the hashmap using the temp_map
            bpf_map_update_elem(&usdt_map, &process_id, temp_map, BPF_ANY);
        } else {
            bpf_printk("Failed to get temp storage for process %d", process_id);
        }
    }

    return 0;
}

SEC("usdt")
int BPF_USDT(trace_php_function_return, void *arg0, void *arg1, void *arg2) {
    pid_t process_id = bpf_get_current_pid_tgid() >> 32;
    
    Map *map = bpf_map_lookup_elem(&usdt_map, &process_id);
    if (map && map->count > 0) {
        // Pop the last function from the stack
        map->count--;
        bpf_printk("PHP[%d] function return: %s() - stack depth now %d", 
                   process_id, map->call_stack[map->count].function_name, map->count);
    } else {
        bpf_printk("PHP[%d] function return but no map found", process_id);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";