#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

#include "Int.h"

static int random_ready = 0;

static bool system_random_bytes(unsigned char *buffer, size_t bytes) {
#if defined(_WIN32) || defined(_WIN64)
        NTSTATUS status = BCryptGenRandom(NULL, buffer, static_cast<ULONG>(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return status == 0;
#else
        size_t total = 0;
        while (total < bytes) {
                ssize_t readed = getrandom(buffer + total, bytes - total, 0);
                if (readed < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        break;
                }
                total += static_cast<size_t>(readed);
        }

        if (total == bytes) {
                return true;
        }

        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
                return false;
        }

        while (total < bytes) {
                ssize_t readed = read(fd, buffer + total, bytes - total);
                if (readed < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        break;
                }
                if (readed == 0) {
                        break;
                }
                total += static_cast<size_t>(readed);
        }

        close(fd);
        return total == bytes;
#endif
}

void int_randominit() {
        if (random_ready) {
                fprintf(stderr, "r_state_mt already initialized, file %s, line %i\n", __FILE__, __LINE__ - 1);
                exit(0);
        }

        unsigned char seed[64];
        if (!system_random_bytes(seed, sizeof(seed))) {
                fprintf(stderr, "Error random_bytes(), file %s, line %i\n", __FILE__, __LINE__ - 2);
                exit(0);
        }

        memset(seed, 0, sizeof(seed));
        random_ready = 1;
}

void Int::Rand(int nbit) {
        if (!random_ready) {
                fprintf(stderr, "Error Rand(), file %s, line %i\n", __FILE__, __LINE__ - 1);
                exit(0);
        }

        size_t byte_len = (nbit + 7) / 8;
        std::vector<unsigned char> bytes(byte_len, 0);
        if (!system_random_bytes(bytes.data(), byte_len)) {
                fprintf(stderr, "Error random_bytes(), file %s, line %i\n", __FILE__, __LINE__ - 1);
                exit(0);
        }

        mpz_import(num, byte_len, 1, sizeof(unsigned char), 0, 0, bytes.data());
        mpz_tdiv_r_2exp(num, num, nbit);
        mpz_setbit(num, nbit - 1);
}

void Int::Rand(Int *min, Int *max) {
        if (!random_ready) {
                fprintf(stderr, "Error Rand(), file %s, line %i\n", __FILE__, __LINE__ - 1);
                exit(0);
        }

        Int diff(max);
        diff.Sub(min);
        int nbit = diff.GetBitLength();
        this->Rand(nbit == 0 ? 1 : nbit);
        this->Mod(&diff);
        this->Add(min);
}

int random_bytes(unsigned char *buffer, int bytes) {
        if (bytes < 0) {
                return -1;
        }
        if (system_random_bytes(buffer, static_cast<size_t>(bytes))) {
                return bytes;
        }
        return -1;
}
