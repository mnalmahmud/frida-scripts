// P1 native shadow: read-only, strict Android API 33 x86_64 ART build IDs.
// No ART objects are modified and no private C++ layout is assumed.
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>
#define EXPORT __attribute__((visibility("default")))
#define COMPILER_ID "0b33b00205f7151b4fce7490c3715d99"
#define RUNTIME_ID "c8b6a2df9893030c07b3b96dc24a7d30"

static int ready = 0;
static uint64_t graphs = 0, gets = 0, sets = 0, rejected = 0;
static uint64_t opaque_graph_word = 0;
static int named(const char *path, const char *base) {
  if (path == NULL) return 0;
  size_t a = strlen(path), b = strlen(base);
  return a >= b && strcmp(path + a - b, base) == 0 &&
         (a == b || path[a - b - 1] == '/');
}
static size_t pad4(size_t n) { return (n + 3u) & ~(size_t)3u; }
static int note_build_id(const struct dl_phdr_info *info, char out[41]) {
  for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
    if (ph->p_type != PT_NOTE || ph->p_filesz > 65536) continue;
    const uint8_t *notes = (const uint8_t *)(info->dlpi_addr + ph->p_vaddr);
    size_t at = 0, length = (size_t)ph->p_filesz;
    while (at + sizeof(ElfW(Nhdr)) <= length) {
      ElfW(Nhdr) nh;
      memcpy(&nh, notes + at, sizeof(nh));
      at += sizeof(nh);
      if (nh.n_namesz > length - at) break;
      const uint8_t *name = notes + at;
      size_t name_bytes = pad4((size_t)nh.n_namesz);
      if (name_bytes > length - at) break;
      at += name_bytes;
      size_t desc_bytes = pad4((size_t)nh.n_descsz);
      if (desc_bytes > length - at) break;
      const uint8_t *desc = notes + at;
      at += desc_bytes;
      if (nh.n_type != NT_GNU_BUILD_ID ||
          nh.n_namesz < 4 || memcmp(name, "GNU", 4) != 0 ||
          nh.n_descsz != 20) continue;
      static const char digits[] = "0123456789abcdef";
      for (size_t k = 0; k < 20; ++k) {
        out[2*k] = digits[desc[k] >> 4];
        out[2*k+1] = digits[desc[k] & 15];
      }
      out[40] = '\0';
      return 1;
    }
  }
  return 0;
}
struct modules { char art[41], compiler[41]; int has_art, has_compiler; };
static int scan(struct dl_phdr_info *info, size_t length, void *arg) {
  (void)length;
  struct modules *m = (struct modules *)arg;
  if (named(info->dlpi_name, "libart.so"))
    m->has_art = note_build_id(info, m->art);
  if (named(info->dlpi_name, "libart-compiler.so"))
    m->has_compiler = note_build_id(info, m->compiler);
  return 0;
}
static int aligned(const void *p) {
  return p != NULL && (((uintptr_t)p) & (sizeof(void *) - 1u)) == 0;
}
EXPORT int artwatch_shadow_init(void) {
  if (ready != 0) return ready == 1;
  char sdk[PROP_VALUE_MAX] = {0};
  if (sizeof(void*) != 8 || __system_property_get("ro.build.version.sdk", sdk) <= 0 ||
      strcmp(sdk, "33") != 0) { ready = -1; return 0; }
  struct modules m = {0};
  dl_iterate_phdr(scan, &m);
  if (!m.has_art || !m.has_compiler ||
      strcmp(m.art, RUNTIME_ID) != 0 ||
      strcmp(m.compiler, COMPILER_ID) != 0) { ready = -1; return 0; }
  ready = 1;
  return 1;
}
// Entry only while the exact matched HGraph* is alive. The first eight bytes
// are opaque; never assume an HGraph layout or retain an object pointer.
EXPORT int artwatch_shadow_graph(const void *graph, const void *builder_graph) {
  if (ready != 1 || !aligned(graph) || graph != builder_graph) {
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED);
    return 0;
  }
  uint64_t word = 0;
  memcpy(&word, graph, sizeof(word));
  __atomic_store_n(&opaque_graph_word, word, __ATOMIC_RELAXED);
  __atomic_fetch_add(&graphs, 1u, __ATOMIC_RELAXED);
  return 1;
}
// Called in Get/Set::Accept. Itanium C++ vptr = exported vtable + 2 words.
// Resolve vtable owner/name, then compare only the first pointer.
EXPORT int artwatch_shadow_node(const void *node, const void *vt_symbol, int kind) {
  if (ready != 1 || !aligned(node) || !aligned(vt_symbol) ||
      (kind != 1 && kind != 2)) {
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED); return 0;
  }
  const char *expected = (kind == 1) ? "_ZTVN3art17HInstanceFieldGetE" :
                                       "_ZTVN3art17HInstanceFieldSetE";
  Dl_info info = {0};
  if (!dladdr(vt_symbol, &info) ||
      !named(info.dli_fname, "libart-compiler.so") ||
      info.dli_sname == NULL || strcmp(info.dli_sname, expected) != 0 ||
      info.dli_saddr != vt_symbol) {
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED); return 0;
  }
  void *vptr = NULL;
  memcpy(&vptr, node, sizeof(vptr));
  if (vptr != (const uint8_t *)vt_symbol + 2*sizeof(void*)) {
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED); return 0;
  }
  if (kind == 1) __atomic_fetch_add(&gets, 1u, __ATOMIC_RELAXED);
  else __atomic_fetch_add(&sets, 1u, __ATOMIC_RELAXED);
  return 1;
}
// Writes only into the caller's scratch buffer, never to ART memory.
EXPORT int artwatch_shadow_report(char *out, uint32_t length) {
  if (out == NULL || length < 96) return 0;
  int n = snprintf(out, length,
    "{\"ready\":%s,\"graphs\":%llu,\"gets\":%llu,\"sets\":%llu,"
    "\"rejected\":%llu,\"opaqueGraphWord\":\"0x%llx\"}",
    ready == 1 ? "true" : "false",
    (unsigned long long)__atomic_load_n(&graphs, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&gets, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&sets, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&rejected, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&opaque_graph_word, __ATOMIC_RELAXED));
  return n > 0 && (uint32_t)n < length ? 1 : 0;
}
