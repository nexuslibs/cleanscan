/*
 * Forces the linker to emit 64-byte aligned .tdata/.tbss sections so the
 * PT_TLS segment of the static musl artifact satisfies Android Bionic's TLS
 * alignment requirement (p_align >= 64 on arm64, >= 32 on arm32). The
 * variables are unreferenced but kept alive by --undefined at link time.
 */
__attribute__((visibility("hidden"))) __thread char cleanscan_tls_pad_tdata __attribute__((aligned(64))) = 1;
__attribute__((visibility("hidden"))) __thread char cleanscan_tls_pad_tbss __attribute__((aligned(64)));
