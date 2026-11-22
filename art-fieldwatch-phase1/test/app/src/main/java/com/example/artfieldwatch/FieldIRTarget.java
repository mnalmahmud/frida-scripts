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

  // Same-graph native invoke template for a future ART Clone()/InsertInstructionAfter.
  // The native sink ignores site=kind=0. No counted event can originate
  // here without compiler injection changing the call's SSA operands.
  public static int p3TemplateCarrierOn(FieldIRTarget receiver, int x) {
    receiver.value = x;
    int observed = identity(receiver).value;
    FieldEventSink.recordInt(0, 0, observed);
    return observed;
  }

  public static int exerciseP3TemplateCarrier(boolean requireInjection)
      throws InterruptedException {
    FieldIRTarget target = new FieldIRTarget();
    for (int i = 0; i < 100000; i++) {
      if (p3TemplateCarrierOn(target, i) != i)
        throw new AssertionError("P3 template warmup mismatch: " + i);
    }
    if (requireInjection) {
      // JIT compilation is asynchronous. In prior CI the 128 reads ran at
      // 09:18:32 while ART didn't insert the invoke until 09:18:34.
      // Keep the call hot until the *successful compiler completion*
      // signal, then allow the runtime to publish the JIT code.
      long deadline = System.nanoTime() + 15_000_000_000L;
      while (!FieldEventSink.p3Enabled()) {
        for (int i = 0; i < 1000; i++) {
          if (p3TemplateCarrierOn(target, i) != i)
            throw new AssertionError("P3 asynchronous warmup mismatch");
        }
        if (System.nanoTime() >= deadline)
          throw new AssertionError("P3 compiler injection was not activated");
        Thread.sleep(20);
      }
      Thread.sleep(200);
      for (int i = 0; i < 2000; i++) {
        if (p3TemplateCarrierOn(target, i) != i)
          throw new AssertionError("P3 published JIT mismatch");
      }
    }
    FieldEventSink.reset();
    int checksum = 0;
    for (int i = 0; i < 128; i++) {
      int expected = 7 + 3 * i;
      int result = p3TemplateCarrierOn(target, expected);
      if (result != expected)
        throw new AssertionError("P3 template value mismatch: " + i);
      checksum += result;
    }
    boolean threw = false;
    try { p3TemplateCarrierOn(null, 777); }
    catch (NullPointerException expected) { threw = true; }
    if (!threw) throw new AssertionError("P3 template null write did not throw");
    if (requireInjection) {
      if (!FieldEventSink.p3Enabled() || !FieldEventSink.p3Verified())
        throw new AssertionError("Compiler-cloned P3 reads missing or incorrect");
    } else if (FieldEventSink.eventCount() != 0) {
      throw new AssertionError("P3 template polluted the event stream");
    }
    return checksum;
  }

  // No explicit sink calls. The only possible future event source is P3 injection.
  public static int p3CanaryOn(FieldIRTarget receiver, int x) {
    receiver.value = x;
    return identity(receiver).value;
  }

  public static int exerciseP3UninstrumentedCanary() {
    FieldIRTarget target = new FieldIRTarget();
    for (int i = 0; i < 100000; i++) {
      if (p3CanaryOn(target, i) != i)
        throw new AssertionError("P3 warmup mismatch: " + i);
    }
    FieldEventSink.reset();
    int checksum = 0;
    for (int i = 0; i < 128; i++) {
      int expected = 7 + 3 * i;
      int result = p3CanaryOn(target, expected);
      if (result != expected)
        throw new AssertionError("P3 canary value mismatch: " + i);
      checksum += result;
    }
    boolean threw = false;
    try {
      p3CanaryOn(null, 777);
    } catch (NullPointerException expected) {
      threw = true;
    }
    if (!threw) throw new AssertionError("P3 null write did not throw");
    if (FieldEventSink.eventCount() != 0)
      throw new AssertionError("Uninstrumented canary emitted events");
    return checksum;
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
