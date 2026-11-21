// Executable P2 event transport. No ART C++ or compiler internals.
// JNI is called only by a deliberately explicit Java fixture in this
// milestone. Compiler-side insertion is a separate, unimplemented step.
// Runtime hot path: bounded fixed storage, atomics, no allocation or locks.
#include <jni.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>

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

// Only the single-purpose CI producer may call reset, after warmup
// finishes and before the measured 128 invocations. Not safe to reset
// while any thread is producing or consuming.
static void clear_events(void) {
  atomic_store_explicit(&next_index, 0, memory_order_relaxed);
  atomic_store_explicit(&dropped, 0, memory_order_relaxed);
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
// Frida polls this *after* Java logs RUNTIME_EVENTS_DONE. The hot
// recorder never formats JSON. Snapshot is read-only and bounded.
// Return 0 when buffer is insufficient or an event is not published yet.
EVENT_EXPORT int artwatch_events_snapshot(char *out, uint32_t length) {
  if (out == NULL || length < 512) return 0;
  const uint32_t total = atomic_load_explicit(&next_index, memory_order_acquire);
  const uint32_t lost = atomic_load_explicit(&dropped, memory_order_acquire);
  const uint32_t stored = total < EVENT_CAPACITY ? total : EVENT_CAPACITY;
  size_t used = 0;
  int written = snprintf(out, length,
    "{\"version\":1,\"total\":%u,\"dropped\":%u,\"capacity\":%u,\"events\":[",
    total, lost, EVENT_CAPACITY);
  if (written < 0 || (size_t)written >= length) return 0;
  used += (size_t)written;
  for (uint32_t i = 0; i < stored; ++i) {
    if (atomic_load_explicit(&ready[i], memory_order_acquire) != 1u) return 0;
    if (used >= length) return 0;
    written = snprintf(out + used, length - used,
      "%s{\"seq\":%u,\"site\":%u,\"kind\":%u,\"value\":%d}",
      i == 0 ? "" : ",", i + 1u,
      events[i].site, events[i].kind, events[i].value);
    if (written < 0 || (size_t)written >= length - used) return 0;
    used += (size_t)written;
  }
  if (used + 3u > length) return 0;
  out[used++] = ']';
  out[used++] = '}';
  out[used] = '\0';
  return 1;
}
