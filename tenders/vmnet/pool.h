/* Persistent, exclusively leased vmnet identities. Same license as Solo5. */
#ifndef SOLO5_VMNET_POOL_H
#define SOLO5_VMNET_POOL_H

#include <sys/file.h>
#include <sys/stat.h>
#include <limits.h>
#include <pwd.h>
#include <uuid/uuid.h>

#define POOL_SIZE 8
#define POOL_MAX 32

struct identity_pool {
    int dir, lock, slot;
    bool saved;
    uuid_t id;
    char mac[18];
    char name[64];
};

static void pool_check_file(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1)
        err(1, "stat pool file");
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid() ||
            (st.st_mode & 077) || st.st_nlink != 1)
        errx(1, "pool files must be private, owned regular files");
}

static unsigned pool_size(const char *value)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    if (errno || !value[0] || *end || n < 1 || n > POOL_MAX)
        errx(2, "pool size must be between 1 and %d", POOL_MAX);
    return (unsigned)n;
}

static void pool_acquire(struct identity_pool *p, const char *directory,
        unsigned count, const char *mode)
{
    char path[PATH_MAX];
    if (!directory) {
        struct passwd *pw = getpwuid(getuid());
        if (!pw)
            errx(1, "cannot find home directory for identity pool");
        if (snprintf(path, sizeof path, "%s/Library/Caches/solo5-vmnet",
                    pw->pw_dir) >= (int)sizeof path)
            errx(1, "identity pool path too long");
        directory = path;
    }
    if (mkdir(directory, 0700) == -1 && errno != EEXIST)
        err(1, "create identity pool %s", directory);
    p->dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (p->dir == -1)
        err(1, "open identity pool %s", directory);
    struct stat st;
    if (fstat(p->dir, &st) == -1)
        err(1, "stat identity pool");
    if (st.st_uid != getuid() || (st.st_mode & 077))
        errx(1, "identity pool directory must be private and owned by this user");

    bool waiting = false;
    for (;;) {
        for (unsigned slot = 0; slot < count; slot++) {
            char name[64];
            snprintf(name, sizeof name, "%s-%u.lock", mode, slot);
            int fd = openat(p->dir, name,
                    O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd == -1)
                err(1, "open pool slot lock");
            pool_check_file(fd);
            if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
                p->lock = fd;
                p->slot = (int)slot;
                snprintf(p->name, sizeof p->name, "%s-%u.identity", mode, slot);
                goto acquired;
            }
            int error = errno;
            close(fd);
            if (error != EWOULDBLOCK)
                errx(1, "lock pool slot: %s", strerror(error));
        }
        if (!waiting)
            fprintf(stderr, "solo5-vmnet: all %u %s pool slots busy; waiting\n",
                    count, mode);
        waiting = true;
        usleep(100000);
    }

acquired:;
    int fd = openat(p->dir, p->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (errno != ENOENT)
            err(1, "read pool identity");
        p->saved = false;
        return;
    }
    pool_check_file(fd);
    char record[128], id[37], mac[18];
    ssize_t n = read(fd, record, sizeof record - 1);
    if (n < 0)
        err(1, "read pool identity");
    close(fd);
    record[n] = 0;
    int consumed = 0;
    if (sscanf(record, "%36s %17s\n%n", id, mac, &consumed) != 2 ||
            consumed != n || uuid_parse(id, p->id) || strlen(mac) != 17)
        errx(1, "invalid pool identity %s; refusing to allocate a replacement",
                p->name);
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2 ? mac[i] != ':' : !isxdigit((unsigned char)mac[i]))
            errx(1, "invalid pool MAC address in %s", p->name);
    }
    strcpy(p->mac, mac);
    p->saved = true;
}

static void pool_save(struct identity_pool *p, const uuid_t id, const char *mac)
{
    if (p->saved) {
        if (uuid_compare(p->id, id) || strcasecmp(p->mac, mac))
            errx(1, "vmnet changed saved identity %s; refusing replacement",
                    p->name);
        return;
    }
    char temporary[96], value[80], text[37];
    uuid_unparse_lower(id, text);
    int length = snprintf(value, sizeof value, "%s %s\n", text, mac);
    snprintf(temporary, sizeof temporary, "%s.tmp", p->name);
    /* A crashed writer may leave this private, slot-specific temporary file. */
    int fd = openat(p->dir, temporary,
            O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == -1)
        err(1, "create pool identity");
    pool_check_file(fd);
    if (ftruncate(fd, 0) == -1 || write(fd, value, (size_t)length) != length ||
            fsync(fd) == -1)
        err(1, "save pool identity");
    close(fd);
    if (renameat(p->dir, temporary, p->dir, p->name) == -1 || fsync(p->dir) == -1)
        err(1, "publish pool identity");
}

#endif
