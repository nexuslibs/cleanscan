/*
 * TLS alignment pad for static musl artifacts.
 *
 * Android Termux (Android 10+) runs every binary through the Bionic linker
 * (/system/bin/linker64 via termux-exec).  It requires the main executable's
 * PT_TLS segment to be at least 64-byte aligned (AArch64) with zero skew, and
 * rejects ET_EXEC entirely, so artifacts must be static PIE with an aligned
 * TLS segment.  These two dummy thread-locals bump the TLS segment alignment
 * to 64 without disturbing any real data.
 */
__attribute__((visibility("hidden"))) __thread char cleanscan_tls_pad_tdata __attribute__((aligned(64))) = 1;
__attribute__((visibility("hidden"))) __thread char cleanscan_tls_pad_tbss __attribute__((aligned(64)));
