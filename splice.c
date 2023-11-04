#include <stdio.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include "splice.skel.h"
#include "splice.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int handle_splice(void *ctx, void *data, size_t data_sz)
{
    struct splice_event *e = data;
    printf("PID: %d, filename: %s\n", e->pid, e->filename);
    int err = kill(e->pid, SIGKILL);
    if (err)
        printf("Failed to kill %d\n", e->pid);
    // clean page cache
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    write(fd, "1", 1);
    close(fd);
    return 0;
}

int main()
{

    struct splice_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);
    skel = splice_bpf__open();
    err = splice_bpf__load(skel);
    if (err)
        goto cleanup;

    err = splice_bpf__attach(skel);
    if (err)
        goto cleanup;

    struct ring_buffer *splice_ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.splice_ringbuf), handle_splice, NULL, NULL);
    if (!splice_ringbuf) {
        err = -1;
        goto cleanup;
    }

    while (true)
    {
        err = ring_buffer__poll(splice_ringbuf, 100);
        if (err == -EINTR || err < 0)
            break;
    }

    cleanup:
    ring_buffer__free(splice_ringbuf);
    splice_bpf__destroy(skel);

    return err;
}
