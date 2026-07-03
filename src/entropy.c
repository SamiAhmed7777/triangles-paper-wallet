/*
 * entropy.c — OS CSPRNG wrapper for portable C11.
 *
 * Tries getrandom() first (Linux 3.17+, glibc 2.25+).
 * Falls back to /dev/urandom on systems that lack it (BSD, macOS, older Linux).
 * Closes the FD as soon as possible.
 */
#define _POSIX_C_SOURCE 200809L
#include "entropy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/syscall.h>
#  include <linux/random.h>
#  define TRI_HAVE_GETRANDOM_SYSCALL 1
#endif

#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
#  include <sys/random.h>
#  define TRI_HAVE_GETRANDOM_LIBC 1
#endif

#if defined(TRI_HAVE_GETRANDOM_LIBC)
static int try_getrandom(uint8_t *out, size_t len)
{
    int total = 0;
    while ((size_t)total < len) {
        ssize_t n = getrandom(out + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        total += (int)n;
    }
    return 0;
}
#elif defined(TRI_HAVE_GETRANDOM_SYSCALL)
static int try_getrandom(uint8_t *out, size_t len)
{
    int total = 0;
    while ((size_t)total < len) {
        long n = syscall(SYS_getrandom, out + total, len - (size_t)total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        total += (int)n;
    }
    return 0;
}
#else
static int try_getrandom(uint8_t *out, size_t len)
{
    (void)out; (void)len;
    errno = ENOSYS;
    return -1;
}
#endif

static int try_urandom(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int total = 0;
    while ((size_t)total < len) {
        ssize_t n = read(fd, out + total, len - (size_t)total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) { close(fd); return -1; }
        total += (int)n;
    }
    close(fd);
    return 0;
}

int get_crypto_entropy(uint8_t *out, size_t len)
{
    if (try_getrandom(out, len) == 0) return 0;
    return try_urandom(out, len);
}
