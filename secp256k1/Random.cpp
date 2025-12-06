/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc Pons.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include "Random.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#if defined(_WIN64) && !defined(__CYGWIN__)
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#endif

static bool system_random_bytes(unsigned char *buffer, size_t bytes) {
#if defined(_WIN64) && !defined(__CYGWIN__)
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

void rseed(unsigned long seed) {
        (void)seed;
}

unsigned long rndl() {
        unsigned long value = 0;
        if (!system_random_bytes(reinterpret_cast<unsigned char *>(&value), sizeof(value))) {
                std::fprintf(stderr, "Unable to read random bytes\n");
                std::exit(EXIT_FAILURE);
        }
        return value;
}

// Returns a uniform distributed double value in the interval ]0,1[
double rnd() {
        uint64_t r = 0;
        if (!system_random_bytes(reinterpret_cast<unsigned char *>(&r), sizeof(r))) {
                std::fprintf(stderr, "Unable to read random bytes\n");
                std::exit(EXIT_FAILURE);
        }

        r >>= 11; // keep 53 random bits
        return (r & ((UINT64_C(1) << 53) - 1)) * (1.0 / 9007199254740992.0);
}
