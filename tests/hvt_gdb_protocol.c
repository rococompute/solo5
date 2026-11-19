/* The script supplies an unchanged production protocol implementation with
 * its platform backend omitted. We supply the backend below and use the real
 * packet receiver, dispatcher, encoders and response sender. */
#include "gdb-module.c"
#include <sys/wait.h>

int hvt_gdb_supported(void) { return 0; }
int hvt_gdb_enable_ss(struct hvt *hvt) { return 0; }
int hvt_gdb_disable_ss(struct hvt *hvt) { return 0; }
int hvt_gdb_read_last_signal(struct hvt *hvt, int *sig) { return -1; }
int hvt_core_register_vmexit(hvt_vmexit_fn_t fn) { return 0; }
int hvt_gdb_read_registers(struct hvt *hvt, uint8_t *reg, size_t *len)
{
    *len = 8;
    memset(reg, 0, *len);
    return 0;
}
int hvt_gdb_write_registers(struct hvt *hvt, uint8_t *reg, size_t len)
{
    assert(len == 8);
    return 0;
}
int hvt_gdb_add_breakpoint(struct hvt *hvt, gdb_breakpoint_type type,
                           hvt_gpa_t addr, size_t len)
{
    assert(type < GDB_BREAKPOINT_MAX);
    return 0;
}
int hvt_gdb_remove_breakpoint(struct hvt *hvt, gdb_breakpoint_type type,
                              hvt_gpa_t addr, size_t len)
{
    assert(type < GDB_BREAKPOINT_MAX);
    return 0;
}

static int checks;
static unsigned char get_byte(int fd)
{
    unsigned char ch;
    if (read(fd, &ch, 1) != 1)
        errx(1, "debugger lost its peer");
    return ch;
}

static void put_byte(int fd, char ch)
{
    if (write(fd, &ch, 1) != 1)
        err(1, "debugger write");
}

static void reply(int fd, char *buf, size_t size)
{
    unsigned char sum = 0;
    size_t n = 0;
    assert(get_byte(fd) == '$');
    for (;;) {
        unsigned char ch = get_byte(fd);
        if (ch == '#')
            break;
        assert(n + 1 < size);
        sum += ch;
        buf[n++] = ch;
    }
    buf[n] = 0;
    assert(hex(get_byte(fd)) == sum >> 4);
    assert(hex(get_byte(fd)) == (sum & 15));
    put_byte(fd, '+');
}

static void request(int fd, const char *packet, const char *expected)
{
    unsigned char sum = 0;
    char buf[BUFMAX + 1];
    put_byte(fd, '$');
    for (const char *p = packet; *p; ++p) {
        sum += (unsigned char)*p;
        put_byte(fd, *p);
    }
    put_byte(fd, '#');
    put_byte(fd, hexchars[sum >> 4]);
    put_byte(fd, hexchars[sum & 15]);
    assert(get_byte(fd) == '+');
    reply(fd, buf, sizeof(buf));
    if (strcmp(buf, expected))
        errx(1, "%s: expected %.40s, got %.40s", packet, expected, buf);
    ++checks;
}

int main(void)
{
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    alarm(20); /* A malformed packet must not wedge the fixture. */
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        close(pair[0]);
        socket_fd = pair[1];
        unsigned char mem[4096];
        memset(mem, 0xab, sizeof(mem));
        struct hvt hvt = {.mem = mem, .guest_mem_size = sizeof(mem)};
        gdb_handle_exception(&hvt, GDB_SIGNAL_TRAP);
        close(pair[1]);
        _exit(0);
    }
    close(pair[1]);
    char buf[BUFMAX + 1];
    reply(pair[0], buf, sizeof(buf));
    assert(!strcmp(buf, "S05"));
    char maximum[BUFMAX - 1];
    for (size_t n = 0; n < sizeof(maximum) - 1; n += 2) {
        maximum[n] = 'a';
        maximum[n + 1] = 'b';
    }
    maximum[sizeof(maximum) - 1] = 0;
    request(pair[0], "m0,7ff", maximum); /* 2047 bytes + NUL fit */
    request(pair[0], "m0,800", "E01"); /* 2048 bytes + NUL do not */
    request(pair[0], "m0,801", "E01");
    request(pair[0], "m0,0", "");
    request(pair[0], "mfff,1", "ab");
    request(pair[0], "m1000,1", "E01");
    request(pair[0], "mffffffffffffffff,2", "E01");
    request(pair[0], "M0,1:cd", "OK");
    request(pair[0], "m0,1", "cd");
    request(pair[0], "M0,2:aa", "E01"); /* short payload */
    request(pair[0], "M0,1:aa00", "E01"); /* long payload */
    request(pair[0], "M0,2:abxy", "E01"); /* invalid hex, no partial write */
    request(pair[0], "m0,1", "cd");
    request(pair[0], "G00", "E01");
    request(pair[0], "G000000000000000g", "E01");
    request(pair[0], "G0000000000000000", "OK");
    request(pair[0], "g", "0000000000000000");
    request(pair[0], "Z5,0,1", "E01");
    request(pair[0], "zffffffff,0,1", "E01");
    request(pair[0], "Z0,0,1", "OK");
    request(pair[0], "D", "OK");
    close(pair[0]);
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("PASS: %d production GDB protocol checks\n", checks);
    return 0;
}
