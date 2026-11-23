// Executable P2 event transport. No ART C++ or compiler internals.
// JNI is called only by a deliberately explicit Java fixture in this
// milestone. Compiler-side insertion is a separate, unimplemented step.
// Runtime hot path: bounded fixed storage, atomics, no allocation or locks.
#include <jni.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define EVENT_EXPORT __attribute__((visibility("default")))
#define EVENT_CAPACITY 512u
struct field_event {
  uint32_t site;
  uint32_t kind;  // 1 = successful read, 2 = successful write
  int32_t value;
};
static struct field_event events[EVENT_CAPACITY];
static atomic_uint ready[EVENT_CAPACITY];
static atomic_uint next_index = 0;
static atomic_uint dropped = 0;
static atomic_uint p3_enabled = 0;
static atomic_uint p3_sentinel_sequence = 0;
// Frozen after P3 verification, before the independent P2 workload resets events.
static struct field_event p3_verified_events[256];
static atomic_uint p3_archive_ready = 0;
static void reset_detailed_events(void);
static int archive_p3_field_metadata(void);
// P3's concrete DEX field identity is installed only after the exact cloned
// invoke nodes survived backend emission. This metadata is immutable while
// the measured fixture runs; it does not establish general app-wide coverage.
static atomic_uint p3_dex_id, p3_method_id, p3_field_id;
static atomic_uint p3_write_pc, p3_read_pc;
static atomic_uint p3_metadata_ready;
EVENT_EXPORT void artwatch_events_record_field(
    uint32_t dex_id, uint32_t method_id, uint32_t field_id,
    uint32_t dex_pc, uint32_t kind, uint32_t type, uint64_t bits);
EVENT_EXPORT int artwatch_events_configure_p3(
    uint32_t dex_id, uint32_t method_id, uint32_t field_id,
    uint32_t write_pc, uint32_t read_pc) {
  if (atomic_load_explicit(&p3_enabled,memory_order_acquire) ||
      atomic_load_explicit(&p3_metadata_ready,memory_order_acquire))
    return 0;
  atomic_store_explicit(&p3_dex_id,dex_id,memory_order_relaxed);
  atomic_store_explicit(&p3_method_id,method_id,memory_order_relaxed);
  atomic_store_explicit(&p3_field_id,field_id,memory_order_relaxed);
  atomic_store_explicit(&p3_write_pc,write_pc,memory_order_relaxed);
  atomic_store_explicit(&p3_read_pc,read_pc,memory_order_relaxed);
  atomic_store_explicit(&p3_metadata_ready,1u,memory_order_release);
  return 1;
}
// Only the controlled fixture sets P3; ordinary P2 events are unchanged.
EVENT_EXPORT void artwatch_events_set_p3(int enabled) {
  atomic_store_explicit(&p3_enabled, enabled ? 1u : 0u, memory_order_release);
}
JNIEXPORT jboolean JNICALL
Java_com_example_artfieldwatch_FieldEventSink_p3Enabled(JNIEnv *env,jclass cls) {
  (void)env; (void)cls;
  return atomic_load_explicit(&p3_enabled,memory_order_acquire) ? JNI_TRUE : JNI_FALSE;
}
JNIEXPORT jboolean JNICALL
Java_com_example_artfieldwatch_FieldEventSink_p3Verified(JNIEnv *env,jclass cls) {
  (void)env; (void)cls;
  if (atomic_load_explicit(&next_index,memory_order_acquire)!=256u ||
      atomic_load_explicit(&dropped,memory_order_acquire)!=0u)
    return JNI_FALSE;
  for (uint32_t i=0;i<128u;++i) {
    if (atomic_load_explicit(&ready[2u*i],memory_order_acquire)!=1u ||
        atomic_load_explicit(&ready[2u*i+1u],memory_order_acquire)!=1u ||
        events[2u*i].site!=9001u || events[2u*i].kind!=2u ||
        events[2u*i].value!=(int32_t)(7u+3u*i) ||
        events[2u*i+1u].site!=9002u || events[2u*i+1u].kind!=1u ||
        events[2u*i+1u].value!=(int32_t)(7u+3u*i))
      return JNI_FALSE;
  }
  // P3 completion must verify both legacy transport AND typed DEX metadata.
  // Archive before P2 resets their independent live measurement buffers.
  if (!archive_p3_field_metadata()) return JNI_FALSE;
  memcpy(p3_verified_events, events, sizeof(p3_verified_events));
  atomic_store_explicit(&p3_archive_ready, 1u, memory_order_release);
  return JNI_TRUE;
}

// Only the single-purpose CI producer may call reset, after warmup
// finishes and before the measured 128 invocations. Not safe to reset
// while any thread is producing or consuming.
static void clear_events(void) {
  atomic_store_explicit(&next_index, 0, memory_order_relaxed);
  atomic_store_explicit(&dropped, 0, memory_order_relaxed);
  atomic_store_explicit(&p3_sentinel_sequence, 0, memory_order_relaxed);
  reset_detailed_events();
  for (uint32_t i = 0; i < EVENT_CAPACITY; ++i)
    atomic_store_explicit(&ready[i], 0, memory_order_relaxed);
}
JNIEXPORT void JNICALL
Java_com_example_artfieldwatch_FieldEventSink_reset(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  clear_events();
}
JNIEXPORT void JNICALL
Java_com_example_artfieldwatch_FieldEventSink_recordInt(
    JNIEnv *env, jclass cls, jint site, jint kind, jint value) {
  (void)env;
  (void)cls;
  // Keep a real, resolved invoke in the P3 template carrier without
  // counting the deliberately inactive site/kind (0,0) as a field event.
  if (site == 0 && kind == 0) {
    if (!atomic_load_explicit(&p3_enabled,memory_order_acquire)) return;
    // ART inserts the cloned call immediately BEFORE the source invoke.
    // Record only cloned write then cloned read calls, not Java source calls.
    // Ignore the original Java-authored sentinel entirely.
    uint32_t n=atomic_fetch_add_explicit(&p3_sentinel_sequence,1u,
                                         memory_order_relaxed);
    if ((n & 1u)!=0u) return;
    site=(n & 2u)==0u ? 9001 : 9002;
    kind=(n & 2u)==0u ? 2 : 1;
    // This P3 adapter still identifies the cloned call by validated
    // clone-before-original ordering. The generic ABI itself does not
    // require that sentinel scheme.
    if (atomic_load_explicit(&p3_metadata_ready,memory_order_acquire)) {
      const uint32_t pc=atomic_load_explicit(
          kind==2 ? &p3_write_pc : &p3_read_pc,memory_order_relaxed);
      artwatch_events_record_field(
          atomic_load_explicit(&p3_dex_id,memory_order_relaxed),
          atomic_load_explicit(&p3_method_id,memory_order_relaxed),
          atomic_load_explicit(&p3_field_id,memory_order_relaxed),
          pc,(uint32_t)kind,5u,(uint64_t)(int64_t)value);
    }
  }
  uint32_t index = atomic_fetch_add_explicit(&next_index, 1u,
                                             memory_order_relaxed);
  if (index >= EVENT_CAPACITY) {
    atomic_fetch_add_explicit(&dropped, 1u, memory_order_relaxed);
    return;
  }
  events[index].site = (uint32_t)site;
  events[index].kind = (uint32_t)kind;
  events[index].value = (int32_t)value;
  atomic_store_explicit(&ready[index], 1u, memory_order_release);
}
// Single-producer negative-control counter. No reset during measurement.
JNIEXPORT jint JNICALL
Java_com_example_artfieldwatch_FieldEventSink_eventCount(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;
  return (jint)atomic_load_explicit(&next_index, memory_order_acquire);
}
// Frida polls this *after* Java logs RUNTIME_EVENTS_DONE. The hot
// recorder never formats JSON. Snapshot is read-only and bounded.
// Return 0 when buffer is insufficient or an event is not published yet.
static int format_events(char *out, uint32_t length,
                         const struct field_event *stored_events,
                         uint32_t total, uint32_t lost, uint32_t count,
                         int check_live_ready) {
  if (out == NULL || length < 512) return 0;
  size_t used = 0;
  int written = snprintf(out, length,
    "{\"version\":1,\"total\":%u,\"dropped\":%u,\"capacity\":%u,\"events\":[",
    total, lost, EVENT_CAPACITY);
  if (written < 0 || (size_t)written >= length) return 0;
  used += (size_t)written;
  for (uint32_t i = 0; i < count; ++i) {
    if (check_live_ready &&
        atomic_load_explicit(&ready[i], memory_order_acquire) != 1u) return 0;
    if (used >= length) return 0;
    written = snprintf(out + used, length - used,
      "%s{\"seq\":%u,\"site\":%u,\"kind\":%u,\"value\":%d}",
      i == 0 ? "" : ",", i + 1u,
      stored_events[i].site, stored_events[i].kind, stored_events[i].value);
    if (written < 0 || (size_t)written >= length - used) return 0;
    used += (size_t)written;
  }
  if (used + 3u > length) return 0;
  out[used++] = ']';
  out[used++] = '}';
  out[used] = '\0';
  return 1;
}

// Export the verified P3 data independently of the later P2 reset.
EVENT_EXPORT int artwatch_events_p3_snapshot(char *out, uint32_t length) {
  if (atomic_load_explicit(&p3_archive_ready, memory_order_acquire) != 1u)
    return 0;
  return format_events(out, length, p3_verified_events, 256u, 0u, 256u, 0);
}

EVENT_EXPORT int artwatch_events_snapshot(char *out, uint32_t length) {
  const uint32_t total = atomic_load_explicit(&next_index, memory_order_acquire);
  const uint32_t lost = atomic_load_explicit(&dropped, memory_order_acquire);
  const uint32_t count = total < EVENT_CAPACITY ? total : EVENT_CAPACITY;
  return format_events(out, length, events, total, lost, count, 1);
}

/*
 * Generic compiler-event ABI (no Java fixture site constants):
 * dex_id identifies the per-APK DEX, method/field IDs are DEX table indices,
 * dex_pc is the instruction's actual DEX code-unit PC.
 * type: 1 boolean, 2 byte, 3 char, 4 short, 5 int, 6 long,
 *       7 float, 8 double, 9 object identity (opaque unsigned bits).
 * value_bits is the exact primitive bit pattern or an opaque reference token.
 * JNI refs must not be held here. Java object identity requires a separate
 * GC-safe producer before it can be supported end-to-end.
 *
 * The ABI is ready for source-matched compiler-side calls. Existing P2/P3
 * recordInt is intentionally untouched until the injector migrates to this.
 */
#define FIELD_METADATA_CAPACITY 4096u
struct detailed_field_event {
  uint32_t dex_id, method_id, field_id, dex_pc, kind, type;
  uint64_t bits;
};
static struct detailed_field_event detailed_events[FIELD_METADATA_CAPACITY];
static atomic_uint detailed_ready[FIELD_METADATA_CAPACITY];
static atomic_uint detailed_count = 0;
static atomic_uint detailed_dropped = 0;
// P3 validated snapshot survives later resets and the explicitly authored P2 workload.
static struct detailed_field_event p3_detailed_verified[256];
static atomic_uint p3_detailed_archive_ready = 0;
static void reset_detailed_events(void) {
  atomic_store_explicit(&detailed_count,0u,memory_order_relaxed);
  atomic_store_explicit(&detailed_dropped,0u,memory_order_relaxed);
  for(uint32_t i=0;i<FIELD_METADATA_CAPACITY;i++)
    atomic_store_explicit(&detailed_ready[i],0u,memory_order_relaxed);
}
JNIEXPORT void JNICALL
Java_com_example_artfieldwatch_FieldEventSink_resetFieldMeta(JNIEnv *env,jclass cls) {
  (void)env; (void)cls;
  reset_detailed_events();
}
JNIEXPORT jint JNICALL
Java_com_example_artfieldwatch_FieldEventSink_fieldMetaCount(JNIEnv *env,jclass cls) {
  (void)env; (void)cls;
  return (jint)atomic_load_explicit(&detailed_count,memory_order_acquire);
}
static int archive_p3_field_metadata(void) {
  if (atomic_load_explicit(&detailed_count,memory_order_acquire)!=256u ||
      atomic_load_explicit(&detailed_dropped,memory_order_acquire)!=0u ||
      !atomic_load_explicit(&p3_metadata_ready,memory_order_acquire)) return 0;
  const uint32_t dex=atomic_load_explicit(&p3_dex_id,memory_order_relaxed);
  const uint32_t method=atomic_load_explicit(&p3_method_id,memory_order_relaxed);
  const uint32_t field=atomic_load_explicit(&p3_field_id,memory_order_relaxed);
  const uint32_t wpc=atomic_load_explicit(&p3_write_pc,memory_order_relaxed);
  const uint32_t rpc=atomic_load_explicit(&p3_read_pc,memory_order_relaxed);
  for(uint32_t i=0;i<256u;i++) {
    if (atomic_load_explicit(&detailed_ready[i],memory_order_acquire)!=1u)
      return 0;
    const struct detailed_field_event *ev=&detailed_events[i];
    const uint32_t kind=(i&1u)==0u ? 2u : 1u;
    if (ev->dex_id!=dex || ev->method_id!=method || ev->field_id!=field ||
        ev->kind!=kind || ev->dex_pc!=(kind==2u?wpc:rpc) ||
        ev->type!=5u || ev->bits!=(uint64_t)(7u+3u*(i/2u)))
      return 0;
  }
  memcpy(p3_detailed_verified,detailed_events,sizeof(p3_detailed_verified));
  atomic_store_explicit(&p3_detailed_archive_ready,1u,memory_order_release);
  return 1;
}
EVENT_EXPORT void artwatch_events_record_field(
    uint32_t dex_id, uint32_t method_id, uint32_t field_id,
    uint32_t dex_pc, uint32_t kind, uint32_t type, uint64_t bits) {
  if ((kind != 1u && kind != 2u) || type < 1u || type > 9u) return;
  const uint32_t slot=atomic_fetch_add_explicit(&detailed_count,1u,memory_order_relaxed);
  if (slot >= FIELD_METADATA_CAPACITY) {
    atomic_fetch_add_explicit(&detailed_dropped,1u,memory_order_relaxed);
    return;
  }
  detailed_events[slot]=(struct detailed_field_event){
    .dex_id=dex_id, .method_id=method_id, .field_id=field_id,
    .dex_pc=dex_pc, .kind=kind, .type=type, .bits=bits
  };
  atomic_store_explicit(&detailed_ready[slot],1u,memory_order_release);
}
// Exact six-int ABI called by the source-matched ART direct injector.
// Signed int32 values are sign-extended into the 64-bit transport.
JNIEXPORT void JNICALL
Java_com_example_artfieldwatch_FieldEventSink_recordFieldInt(
    JNIEnv *env,jclass cls,jint dex_id,jint method_id,jint field_id,
    jint dex_pc,jint kind,jint value) {
  (void)env; (void)cls;
  if (dex_id<0 || method_id<0 || field_id<0 || dex_pc<0) return;
  artwatch_events_record_field((uint32_t)dex_id,(uint32_t)method_id,
    (uint32_t)field_id,(uint32_t)dex_pc,(uint32_t)kind,5u,
    (uint64_t)(int64_t)(int32_t)value);
}
EVENT_EXPORT int artwatch_events_field_snapshot(char *out,uint32_t length) {
  if (out==NULL || length<128u) return 0;
  const uint32_t total=atomic_load_explicit(&detailed_count,memory_order_acquire);
  const uint32_t dropped=atomic_load_explicit(&detailed_dropped,memory_order_acquire);
  const uint32_t stored=total<FIELD_METADATA_CAPACITY ? total:FIELD_METADATA_CAPACITY;
  size_t used=0;
  int n=snprintf(out,length,
    "{\"version\":2,\"total\":%u,\"dropped\":%u,\"events\":[",total,dropped);
  if (n<0 || (size_t)n>=length) return 0;
  used+=(size_t)n;
  for(uint32_t i=0;i<stored;i++) {
    if (atomic_load_explicit(&detailed_ready[i],memory_order_acquire)!=1u)
      return 0;
    const struct detailed_field_event *e=&detailed_events[i];
    n=snprintf(out+used,length-used,
      "%s{\"seq\":%u,\"dexId\":%u,\"methodId\":%u,"
      "\"fieldId\":%u,\"dexPc\":%u,\"kind\":%u,\"type\":%u,"
      "\"valueBits\":\"0x%016llx\"}", i?",":"",
      i+1u,e->dex_id,e->method_id,e->field_id,e->dex_pc,
      e->kind,e->type,(unsigned long long)e->bits);
    if (n<0 || (size_t)n>=length-used) return 0;
    used+=(size_t)n;
  }
  if (used+3u>length) return 0;
  out[used++]=']';out[used++]='}';out[used]='\0';
  return 1;
}

EVENT_EXPORT int artwatch_events_p3_field_snapshot(char *out,uint32_t length) {
  if (atomic_load_explicit(&p3_detailed_archive_ready,memory_order_acquire)!=1u ||
      out==NULL || length<128u) return 0;
  size_t used=0;
  int n=snprintf(out,length,
    "{\"version\":2,\"total\":256,\"dropped\":0,\"events\":[");
  if (n<0 || (size_t)n>=length) return 0;
  used+=(size_t)n;
  for(uint32_t i=0;i<256u;i++) {
    const struct detailed_field_event *e=&p3_detailed_verified[i];
    n=snprintf(out+used,length-used,
      "%s{\"seq\":%u,\"dexId\":%u,\"methodId\":%u,"
      "\"fieldId\":%u,\"dexPc\":%u,\"kind\":%u,\"type\":%u,"
      "\"valueBits\":\"0x%016llx\"}",i?",":"",
      i+1u,e->dex_id,e->method_id,e->field_id,e->dex_pc,
      e->kind,e->type,(unsigned long long)e->bits);
    if (n<0 || (size_t)n>=length-used) return 0;
    used+=(size_t)n;
  }
  if (used+3u>length) return 0;
  out[used++]=']';out[used++]='}';out[used]='\0';
  return 1;
}
