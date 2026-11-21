package com.example.artfieldwatch;

/** Deliberately tiny DEX iget/iput test for compiler IR experiments. */
public final class FieldIRTarget {
  private int value;

  public int test(int x) {
    value = x;
    return value;
  }

  // An opaque helper prevents purely intra-method DEX simplification
  // while giving ART's optimizing JIT an inlining opportunity.
  private static FieldIRTarget identity(FieldIRTarget target) {
    return target;
  }

  public int testViaIdentity(int x) {
    value = x;
    return identity(this).value;
  }

  // Keep these alternate JIT compilation sites structurally distinct.
  // The helper makes the value read visible in release DEX while ART
  // can inline the helper and eliminate redundant field operations.
  public static int exerciseOverwrites(int iterations) {
    FieldIRTarget target = new FieldIRTarget();
    int checksum = 0;
    for (int i = 0; i < iterations; i++) {
      target.value = i;
      target.value = i + 1;
      int observed = identity(target).value;
      if (observed != i + 1) {
        throw new AssertionError("Overwrite read mismatch at " + i);
      }
      checksum += observed & 1;
    }
    return checksum;
  }

  public static int exerciseAlternating(int iterations) {
    FieldIRTarget target = new FieldIRTarget();
    int checksum = 0;
    for (int i = 0; i < iterations; i++) {
      int expected;
      if ((i & 1) == 0) {
        target.value = i;
        expected = i;
      } else {
        target.value = i + 1;
        expected = i + 1;
      }
      int observed = identity(target).value;
      if (observed != expected) {
        throw new AssertionError("Alternating read mismatch at " + i);
      }
      checksum += observed & 1;
    }
    return checksum;
  }

  // First executable field-event path. The calls are explicit in Java
  // bytecode for now; future compiler injection must place equivalent
  // side-effecting calls at the successful field-access IR boundary.
  public static int watchedOn(FieldIRTarget receiver, int x) {
    receiver.value = x; // Throws on null BEFORE any write event.
    FieldEventSink.recordInt(FieldEventSink.SITE_WRITE_VALUE,
                             FieldEventSink.WRITE, x);
    int observed = identity(receiver).value;
    FieldEventSink.recordInt(FieldEventSink.SITE_READ_VALUE,
                             FieldEventSink.READ, observed);
    return observed;
  }

  public static int exerciseRuntimeEvents() {
    FieldIRTarget target = new FieldIRTarget();
    // Heat the same method before reset, allowing the JIT to compile it
    // naturally. The measured phase contains exactly 128 calls.
    for (int i = 0; i < 100000; i++) {
      if (watchedOn(target, i) != i)
        throw new AssertionError("Native event warmup mismatch at " + i);
    }
    FieldEventSink.reset();
    int checksum = 0;
    for (int i = 0; i < 128; i++) {
      int expected = 7 + 3 * i;
      int result = watchedOn(target, expected);
      if (result != expected)
        throw new AssertionError("Native event value mismatch at " + i);
      checksum += result;
    }
    // Null receiver must throw before any successful access callback.
    boolean threw = false;
    try {
      watchedOn(null, 777);
    } catch (NullPointerException expected) {
      threw = true;
    }
    if (!threw)
      throw new AssertionError("Null write did not throw NPE");
    return checksum;
  }

  public static int warmup(int iterations) {
    FieldIRTarget target = new FieldIRTarget();
    int observed = 0;
    for (int i = 0; i < iterations; i++) {
      if (target.test(i) != i) {
        throw new AssertionError("FieldIRTarget direct read/write mismatch at " + i);
      }
      if (target.testViaIdentity(i) != i) {
        throw new AssertionError("FieldIRTarget identity read/write mismatch at " + i);
      }
      observed++;
    }
    return observed;
  }
}
