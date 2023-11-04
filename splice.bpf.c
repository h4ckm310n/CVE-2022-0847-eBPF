//
// Created by h4ckm310n on 2023/6/8.
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "splice.h"
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} splice_ringbuf SEC(".maps");

SEC("tp/syscalls/sys_enter_splice")
int handle_splice(struct trace_event_raw_sys_enter *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // splice(fd, &offset, p[1], NULL, 1, 0);
    int file_fd = ctx->args[0];
    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
    struct file *f;
    bpf_probe_read(&f, sizeof(f), &fd[file_fd]);
    struct qstr d_name = BPF_CORE_READ(f, f_path.dentry, d_name);

    int pipe_fd = ctx->args[2];
    bpf_probe_read(&f, sizeof(f), &fd[pipe_fd]);
    umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);

    // not a pipe, S_ISFIFO
    if (((mode) & 00170000) != 0010000)
        return 0;

    // /fs/pipe.c
    struct pipe_inode_info *i_pipe = (struct pipe_inode_info *) BPF_CORE_READ(f, private_data);
    unsigned int ring_size = BPF_CORE_READ(i_pipe, ring_size);
    struct pipe_buffer *bufs = BPF_CORE_READ(i_pipe, bufs);
    struct pipe_buffer buf;
    bpf_probe_read(&buf, sizeof(buf), &bufs[ring_size-1]);
    unsigned int flags = buf.flags;

    // flags is not set
    if (!(flags & PIPE_BUF_FLAG_CAN_MERGE))
        return 0;

    struct splice_event *e = bpf_ringbuf_reserve(&splice_ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    e->pid = pid;
    bpf_probe_read(e->filename, sizeof(e->filename), d_name.name);
    bpf_ringbuf_submit(e, 0);

    return 0;
}