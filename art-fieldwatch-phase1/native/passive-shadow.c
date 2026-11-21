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
static uint64_t graphs = 0, gets = 0, sets = 0, rejected = 0, blocks = 0;
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
      // Android ART may use 16-byte GNU Build IDs (32 hex digits),
      // rather than the common 20-byte IDs (40 hex digits). The output
      // buffer holds at most 40 digits plus a NUL terminator.
      if (nh.n_type != NT_GNU_BUILD_ID ||
          nh.n_namesz < 4 || memcmp(name, "GNU", 4) != 0 ||
          (nh.n_descsz != 16 && nh.n_descsz != 20)) continue;
      static const char digits[] = "0123456789abcdef";
      for (size_t k = 0; k < nh.n_descsz; ++k) {
        out[2*k] = digits[desc[k] >> 4];
        out[2*k+1] = digits[desc[k] & 15];
      }
      out[2u * nh.n_descsz] = '\0';
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
// Per-native-thread, fixed-capacity, observation-only visitor inventory.
// Compiler workers are not asked to allocate or call back into Java.
// This records only field nodes whose Accept() method is invoked while
// RunOptimizations() is executing. It is NOT an HGraph block traversal.
#define SHADOW_MAX_UNIQUE 512u
struct scope {
  const void *graph;
  uint32_t get_visits, set_visits, unique_gets, unique_sets, overflow;
  const void *nodes[SHADOW_MAX_UNIQUE];
  uint8_t kinds[SHADOW_MAX_UNIQUE];
};
static __thread struct scope scoped;
EXPORT int artwatch_shadow_scope_begin(const void *graph) {
  if (ready != 1 || !aligned(graph) || scoped.graph != NULL) return 0;
  memset(&scoped, 0, sizeof(scoped));
  scoped.graph = graph;
  return 1;
}
EXPORT int artwatch_shadow_scope_end(char *out, uint32_t length) {
  if (ready != 1 || out == NULL || length < 128 || scoped.graph == NULL)
    return 0;
  int n = snprintf(out, length,
    "{\"graph\":\"%p\",\"getVisits\":%u,\"setVisits\":%u,"
    "\"uniqueGets\":%u,\"uniqueSets\":%u,\"overflow\":%u}",
    scoped.graph, scoped.get_visits, scoped.set_visits,
    scoped.unique_gets, scoped.unique_sets, scoped.overflow);
  // Clear the observation window even if formatting somehow fails.
  scoped.graph = NULL;
  return n > 0 && (uint32_t)n < length ? 1 : 0;
}
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
// Read-only validation of pointers exposed by HGraph::AddBlock.
 // We never dereference an HBasicBlock, and we store no block pointers.
EXPORT int artwatch_shadow_block(const void *graph,
                                const void *builder_graph,
                                const void *block) {
  if (ready != 1 || !aligned(graph) || graph != builder_graph ||
      !aligned(block)) {
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED);
    return 0;
  }
  __atomic_fetch_add(&blocks, 1u, __ATOMIC_RELAXED);
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
  if (scoped.graph != NULL) {
    if (kind == 1) scoped.get_visits++;
    else scoped.set_visits++;
    uint32_t used = scoped.unique_gets + scoped.unique_sets;
    int seen = 0;
    for (uint32_t i = 0; i < used; i++) {
      if (scoped.nodes[i] == node && scoped.kinds[i] == (uint8_t)kind) {
        seen = 1;
        break;
      }
    }
    if (!seen) {
      if (used < SHADOW_MAX_UNIQUE) {
        scoped.nodes[used] = node;
        scoped.kinds[used] = (uint8_t)kind;
        if (kind == 1) scoped.unique_gets++;
        else scoped.unique_sets++;
      } else {
        scoped.overflow++;
      }
    }
  }
  return 1;
}
// Source-layout experiment: the Itanium x86_64 HInstruction object has
// vptr, previous_, next_, block_ as its first four machine words in the
// Android 13 compiler. Match only *already live* vtable-confirmed nodes
// passed by Frida Accept observers, after the exact mapped-ELF gate.
// On any mismatch, fail closed. This function NEVER mutates ART memory.
// Return 1 for adjacent get->invoke with reciprocal links and block;
// 0 for nonadjacency; -1 for invalid gate / object identity.
EXPORT int artwatch_shadow_linked_get_invoke(
    const void *getter, const void *invoke,
    const void *get_vtable, const void *invoke_vtable) {
  if (ready != 1 || !aligned(getter) || !aligned(invoke) ||
      !aligned(get_vtable) || !aligned(invoke_vtable)) return -1;
  // Confirm that the public vtable symbols belong to the mapped compiler.
  const char *symbol_names[2] = {
    "_ZTVN3art17HInstanceFieldGetE",
    "_ZTVN3art21HInvokeStaticOrDirectE"
  };
  const void *vt[2] = {get_vtable, invoke_vtable};
  const void *objects[2] = {getter, invoke};
  for (size_t i = 0; i < 2; ++i) {
    Dl_info info = {0};
    if (!dladdr(vt[i], &info) ||
        !named(info.dli_fname, "libart-compiler.so") ||
        info.dli_sname == NULL ||
        strcmp(info.dli_sname, symbol_names[i]) != 0 ||
        info.dli_saddr != vt[i]) return -1;
    void *actual = NULL;
    memcpy(&actual, objects[i], sizeof(actual));
    if (actual != (const uint8_t *)vt[i] + 2 * sizeof(void*)) return -1;
  }
  // First four pointers are vptr, previous_, next_, HBasicBlock*.
  // Read only known, live, already-vtable-confirmed instruction objects.
  const uint8_t *g = (const uint8_t *)getter;
  const uint8_t *i = (const uint8_t *)invoke;
  const void *g_next = NULL, *i_prev = NULL;
  const void *g_block = NULL, *i_block = NULL;
  memcpy(&g_next, g + 2 * sizeof(void*), sizeof(g_next));
  memcpy(&i_prev, i + 1 * sizeof(void*), sizeof(i_prev));
  memcpy(&g_block, g + 3 * sizeof(void*), sizeof(g_block));
  memcpy(&i_block, i + 3 * sizeof(void*), sizeof(i_block));
  return g_next == invoke && i_prev == getter &&
         g_block != NULL && i_block == g_block ? 1 : 0;
}
// Writes only into the caller's scratch buffer, never to ART memory.
EXPORT int artwatch_shadow_report(char *out, uint32_t length) {
  if (out == NULL || length < 96) return 0;
  int n = snprintf(out, length,
    "{\"ready\":%s,\"graphs\":%llu,\"gets\":%llu,\"sets\":%llu,"
    "\"blocks\":%llu,\"rejected\":%llu,\"opaqueGraphWord\":\"0x%llx\"}",
    ready == 1 ? "true" : "false",
    (unsigned long long)__atomic_load_n(&graphs, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&gets, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&sets, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&blocks, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&rejected, __ATOMIC_RELAXED),
    (unsigned long long)__atomic_load_n(&opaque_graph_word, __ATOMIC_RELAXED));
  return n > 0 && (uint32_t)n < length ? 1 : 0;
}
