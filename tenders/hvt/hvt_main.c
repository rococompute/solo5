/*
 * Copyright (c) 2015-2019 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a sandboxed execution environment.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * hvt_main.c: Main program.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "hvt.h"
#include "version.h"

/*
 * Bounds of the "modules" section populated by DECLARE_MODULE(). GNU ld and
 * LLD synthesise __start_/__stop_ symbols for named sections; ld64 instead
 * provides section$start$/section$end$ magic symbols per segment and section.
 */
#if defined(__APPLE__)
extern struct hvt_module __start_modules __asm("section$start$__DATA$modules");
extern struct hvt_module __stop_modules __asm("section$end$__DATA$modules");
#else
extern struct hvt_module __start_modules;
extern struct hvt_module __stop_modules;
#endif

static void setup_modules(struct hvt *hvt, struct mft *mft)
{
    for (struct hvt_module *m = &__start_modules; m < &__stop_modules; m++) {
        assert(m->ops.setup);
        if (m->ops.setup(hvt, mft)) {
            warnx("Module `%s' setup failed", m->name);
            if (m->ops.usage) {
                warnx("Please check you have correctly specified:\n    %s",
                      m->ops.usage());
            }
            exit(1);
        }
    }

    bool fail = false;
    for (unsigned i = 0; i != mft->entries; i++) {
        if (mft->e[i].type >= MFT_RESERVED_FIRST)
            continue;
        if (!mft->e[i].attached) {
            warnx("Device '%s' of type %s declared but not attached.",
                  mft->e[i].name, mft_type_to_string(mft->e[i].type));
            fail = true;
        }
    }
    if (fail)
        errx(1, "All declared devices must be attached. "
                "See --help for syntax.");
}

static int handle_cmdarg(char *cmdarg, struct mft *mft)
{
    for (struct hvt_module *m = &__start_modules; m < &__stop_modules; m++) {
        if (m->ops.handle_cmdarg) {
            if (m->ops.handle_cmdarg(cmdarg, mft) == 0) {
                return 0;
            }
        }
    }
    return -1;
}

static void sig_handler(int signo)
{
    errx(1, "Exiting on signal %d", signo);
}

/*
 * --exit-report=FD
 *
 * A supervisor running untrusted unikernels needs to tell the guest's own
 * exit status apart from the tender killing a misbehaving guest, and both
 * apart from the tender failing. Exit codes alone overlap (errx() exits 1,
 * as does a guest calling solo5_exit(1)), so on exit write one JSON line to
 * FD instead:
 *
 *   {"kind":"guest_exit","status":N}       guest called solo5_exit(N)
 *   {"kind":"guest_abort","status":255}    guest called solo5_abort()
 *   {"kind":"fault","reason":R,"message":M}
 *       the tender stopped the guest: R is "translation_fault" (guest W^X
 *       or bounds violation), "invalid_access" (bad hypercall or MMIO),
 *       "exception" (unhandled guest exception) or "cpu_limit"
 *   {"kind":"signal","message":M}          SIGINT or SIGTERM
 *   {"kind":"tender_error","message":M}    anything else
 *
 * Messages come from err(3)/warn(3), which on hosts that support it are
 * teed through report_err_write() so that the last one is known whichever
 * errx() call site ended the tender.
 */
static int exit_report_fd = -1;
static int exit_report_guest_status = -1;
static char last_err[512];
static size_t last_err_len;
static char err_line[512];
static size_t err_line_len;

static void report_err_bytes(const char *buf, size_t len)
{
    (void)!write(STDERR_FILENO, buf, (size_t)len);
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            memcpy(last_err, err_line, err_line_len);
            last_err_len = err_line_len;
            err_line_len = 0;
        } else if (err_line_len < sizeof err_line) {
            err_line[err_line_len++] = buf[i];
        }
    }
}

#if defined(__GLIBC__)
static ssize_t report_err_write(void *cookie, const char *buf, size_t len)
#else
static int report_err_write(void *cookie, const char *buf, int len)
#endif
{
    (void)cookie;
    report_err_bytes(buf, (size_t)len);
    return len;
}

static size_t json_escape(char *dst, size_t dstlen, const char *src,
                          size_t srclen)
{
    size_t o = 0;
    for (size_t i = 0; i < srclen && o + 7 < dstlen; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)c;
        } else if (c < 0x20 || c >= 0x7f) {
            o += (size_t)snprintf(dst + o, dstlen - o, "\\u%04x", c);
        } else {
            dst[o++] = (char)c;
        }
    }
    dst[o] = 0;
    return o;
}

static void exit_report(void)
{
    char line[1024], msg[600];
    int n;

    if (exit_report_fd == -1)
        return;
    if (exit_report_guest_status == 255) {
        n = snprintf(line, sizeof line,
                     "{\"kind\":\"guest_abort\",\"status\":255}\n");
    } else if (exit_report_guest_status >= 0) {
        n = snprintf(line, sizeof line,
                     "{\"kind\":\"guest_exit\",\"status\":%d}\n",
                     exit_report_guest_status);
    } else {
        json_escape(msg, sizeof msg, last_err, last_err_len);
        const char *kind = "tender_error", *reason = NULL;
        if (strstr(msg, "translation fault"))
            kind = "fault", reason = "translation_fault";
        else if (strstr(msg, "Invalid guest"))
            kind = "fault", reason = "invalid_access";
        else if (strstr(msg, "unhandled exception"))
            kind = "fault", reason = "exception";
        else if (strstr(msg, "CPU time limit"))
            kind = "fault", reason = "cpu_limit";
        else if (strstr(msg, "Exiting on signal"))
            kind = "signal";
        if (reason)
            n = snprintf(line, sizeof line,
                         "{\"kind\":\"%s\",\"reason\":\"%s\","
                         "\"message\":\"%s\"}\n",
                         kind, reason, msg);
        else
            n = snprintf(line, sizeof line,
                         "{\"kind\":\"%s\",\"message\":\"%s\"}\n", kind,
                         msg);
    }
    if (n > 0)
        (void)!write(exit_report_fd, line,
                     (size_t)n < sizeof line ? (size_t)n : sizeof line - 1);
}

static void handle_exit_report(char *cmdarg)
{
    int fd;
    char extra;
    if (sscanf(cmdarg, "--exit-report=%d%c", &fd, &extra) != 1 || fd < 0)
        errx(1, "Malformed argument to --exit-report");
    if (fcntl(fd, F_GETFD) == -1)
        err(1, "--exit-report=%d", fd);
    exit_report_fd = fd;
#if defined(__GLIBC__)
    cookie_io_functions_t io = {.write = report_err_write};
    FILE *f = fopencookie(NULL, "w", io);
#else
    FILE *f = fwopen(NULL, report_err_write);
#endif
    if (f == NULL)
        err(1, "could not open exit-report error stream");
    setvbuf(f, NULL, _IONBF, 0);
#if defined(__GLIBC__)
    /* glibc's err()/warn() use stderr; it has no BSD err_set_file().
     * Keep the original descriptor as the tee destination, not this FILE. */
    stderr = f;
#else
    err_set_file(f);
#endif
    if (atexit(exit_report) != 0)
        errx(1, "atexit failed");
}

/*
 * --cpu-limit=SECONDS
 *
 * Bound the CPU time the tender (and so the guest) may use. A watchdog thread
 * checks the process CPU time every 100ms and ends the tender once the limit
 * is exceeded; this is reported as a fault with reason "cpu_limit".
 *
 * RLIMIT_CPU would be the obvious mechanism, but on macOS 26 with
 * Hypervisor.framework a process with RLIMIT_CPU set livelocks inside
 * hv_vcpu_run() and never runs the guest, whatever the limit.
 */
static long cpu_limit_secs;

static void *cpu_limit_watchdog(void *arg)
{
    (void)arg;
    for (;;) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&ts, NULL);
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0 &&
            ts.tv_sec >= cpu_limit_secs)
            errx(1, "CPU time limit of %ld seconds exceeded", cpu_limit_secs);
    }
    return NULL;
}

static void handle_cpu_limit(char *cmdarg)
{
    char extra;
    if (sscanf(cmdarg, "--cpu-limit=%ld%c", &cpu_limit_secs, &extra) != 1 ||
        cpu_limit_secs <= 0)
        errx(1, "Malformed argument to --cpu-limit");
}

static void start_cpu_limit_watchdog(void)
{
    pthread_t t;
    if (cpu_limit_secs == 0)
        return;
    if (pthread_create(&t, NULL, cpu_limit_watchdog, NULL) != 0)
        errx(1, "Could not start the CPU limit watchdog");
    pthread_detach(t);
}

static void handle_mem(char *cmdarg, size_t *mem_size)
{
    size_t mem;
    int rc = sscanf(cmdarg, "--mem=%zd", &mem);
    mem = mem << 20;
    if (rc != 1 || mem <= 0) {
        errx(1, "Malformed argument to --mem");
    }
    *mem_size = mem;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [ CORE OPTIONS ] [ MODULE OPTIONS ] [ -- ] "
            "KERNEL [ ARGS ]\n",
            prog);
    fprintf(stderr, "KERNEL is the filename of the unikernel to run.\n");
    fprintf(stderr, "ARGS are optional arguments passed to the unikernel.\n");
    fprintf(stderr, "Core options:\n");
    fprintf(stderr, "  [ --mem=512 ] (guest memory in MB)\n");
    fprintf(stderr, "  [ --no-net-ring ] (disable the net ring buffer)\n");
    fprintf(stderr, "  [ --no-random ] (do not give the guest host random"
                    " bytes)\n");
    fprintf(stderr, "  [ --cpu-limit=SECONDS ] (limit CPU time used)\n");
    fprintf(stderr, "  [ --exit-report=FD ] (write a JSON exit report to FD)\n");
    fprintf(stderr, "    --help (display this help)\n");
    fprintf(stderr, "    --version (display version information)\n");
    fprintf(stderr, "Compiled-in modules: ");
    for (struct hvt_module *m = &__start_modules; m < &__stop_modules; m++) {
        fprintf(stderr, "%s ", m->name);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "Compiled-in module options:\n");
    int nm = 0;
    for (struct hvt_module *m = &__start_modules; m < &__stop_modules; m++) {
        if (m->ops.usage) {
            fprintf(stderr, "    %s\n", m->ops.usage());
            nm++;
        }
    }
    if (!nm)
        fprintf(stderr, "    (none)\n");
    exit(1);
}

static void version(const char *prog)
{
    fprintf(stderr, "%s tender, version %s\n", prog, SOLO5_VERSION);
    fprintf(stderr, "ABI version %u\n", HVT_ABI_VERSION);
    exit(0);
}

int main(int argc, char **argv)
{
    size_t mem_size = 0x20000000;
    int no_net_ring = 0;
    hvt_gpa_t gpa_ep, gpa_kend;
    const char *prog;
    const char *elf_filename;
    int elf_fd = -1;

    prog = basename(*argv);
    argc--;
    argv++;

    /*
     * Scan command line arguments, looking for the first non-option argument
     * which will be the ELF file to load. Stop if a "terminal" option such as
     * --help is encountered.
     */
    char **argv1 = argv;
    while (*argv1 && *argv1[0] == '-') {
        if (strcmp("--", *argv1) == 0) {
            /* Consume and stop option processing */
            argv1++;
            break;
        }

        if (strcmp("--help", *argv1) == 0)
            usage(prog);
        else if (strcmp("--version", *argv1) == 0)
            version(prog);

        argv1++;
    }
    if (*argv1 == NULL) {
        warnx("Missing KERNEL operand");
        usage(prog);
    }
    elf_filename = *argv1;

    /*
     * Now that we have the ELF file name, verify that is binary is
     * ABI-compatible and load the MFT1 NOTE from it, as subsequent parsing of
     * the command line in the 2nd pass depends on the application-supplied
     * manifest.
     */
    elf_fd = open(elf_filename, O_RDONLY);
    if (elf_fd == -1)
        err(1, "%s: Could not open", elf_filename);

    struct abi1_info *abi1;
    size_t abi1_size;
    if (elf_load_note(elf_fd, elf_filename, ABI1_NOTE_TYPE, ABI1_NOTE_ALIGN,
                      sizeof(struct abi1_info), ABI1_NOTE_MAX_SIZE,
                      (void **)&abi1, &abi1_size) == -1)
        errx(1, "%s: No Solo5 ABI information found in executable",
             elf_filename);
    if (abi1->abi_target != HVT_ABI_TARGET)
        errx(1, "%s: Executable is not for the solo5-hvt target", elf_filename);
    if (abi1->abi_version != HVT_ABI_VERSION)
        errx(1, "%s: Executable requests unsupported ABI version %u",
             elf_filename, abi1->abi_version);
    free(abi1);

    struct mft *mft;
    size_t mft_size;
    if (elf_load_note(elf_fd, elf_filename, MFT1_NOTE_TYPE, MFT1_NOTE_ALIGN,
                      sizeof(struct mft), MFT1_NOTE_MAX_SIZE, (void **)&mft,
                      &mft_size) == -1)
        errx(1, "%s: No Solo5 manifest found in executable", elf_filename);
    if (mft_validate(mft, mft_size) == -1) {
        free(mft);
        errx(1, "%s: Solo5 manifest is invalid", elf_filename);
    }

    /*
     * Scan command line arguments in a 2nd pass, and pass options through to
     * modules to handle.
     */
    while (*argv && *argv[0] == '-') {
        if (strcmp("--", *argv) == 0) {
            /* Consume and stop option processing */
            argc--;
            argv++;
            break;
        }

        if (strncmp("--mem=", *argv, 6) == 0) {
            handle_mem(*argv, &mem_size);
            argc--;
            argv++;
            continue;
        }
        if (strncmp("--exit-report=", *argv, 14) == 0) {
            handle_exit_report(*argv);
            argc--;
            argv++;
            continue;
        }
        if (strncmp("--cpu-limit=", *argv, 12) == 0) {
            handle_cpu_limit(*argv);
            argc--;
            argv++;
            continue;
        }
        if (strncmp("--no-net-ring", *argv, sizeof("--no-net-ring")) == 0) {
            no_net_ring = 1;
            argc--;
            argv++;
            continue;
        }
        if (strcmp("--no-random", *argv) == 0) {
            hvt_core_disable_random();
            argc--;
            argv++;
            continue;
        }
        if (handle_cmdarg(*argv, mft) == 0) {
            /* Handled by module, consume and go on to next arg */
            argc--;
            argv++;
            continue;
        }
        warnx("Invalid option: `%s'", *argv);
        usage(prog);
    }
    assert(elf_filename == *argv);
    argc--;
    argv++;

    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = sig_handler;
    sigfillset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        err(1, "Could not install signal handler");
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        err(1, "Could not install signal handler");

    hvt_mem_size(&mem_size);
    struct hvt *hvt = hvt_init(mem_size);

    if (no_net_ring == 0)
        hvt_net_reserve_ring(hvt, mft);
    elf_load(elf_fd, elf_filename, hvt->mem, hvt->guest_mem_size,
             HVT_GUEST_MIN_BASE, hvt_guest_mprotect, hvt, &gpa_ep, &gpa_kend);
    close(elf_fd); /* Done with ELF binary */

    hvt_vcpu_init(hvt, gpa_ep);

    setup_modules(hvt, mft);

    hvt_boot_info_init(hvt, gpa_kend, argc, argv, mft, mft_size);

    /* Threads must exist before privileges are dropped (see pledge(2)). */
    start_cpu_limit_watchdog();

#if defined(HVT_DROP_PRIVILEGES) && HVT_DROP_PRIVILEGES == 1
    hvt_drop_privileges();
#else
    warnx("WARNING: Tender is configured with HVT_DROP_PRIVILEGES=0. Not"
          " dropping any privileges.");
    warnx("WARNING: This is not recommended for production use.");
#endif

    int status = hvt_vcpu_loop(hvt);
    exit_report_guest_status = status;
    return status;
}
