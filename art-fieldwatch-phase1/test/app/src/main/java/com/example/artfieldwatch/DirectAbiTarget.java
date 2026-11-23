package com.example.artfieldwatch;

/** Explicit JNI ABI contract for the direct compiler sink; NOT ART injection. */
public final class DirectAbiTarget {
  private int value;
  private static int shared;

  public static int exercise() {
    FieldEventSink.resetFieldMeta();
    DirectAbiTarget target = new DirectAbiTarget();
    target.value = -11;
    FieldEventSink.recordFieldInt(0, 3, 17, 7, FieldEventSink.WRITE, -11);
    int observed = target.value;
    FieldEventSink.recordFieldInt(0, 3, 17, 9, FieldEventSink.READ, observed);
    shared = 42;
    FieldEventSink.recordFieldInt(0, 4, 18, 11, FieldEventSink.WRITE, 42);
    int staticObserved = shared;
    FieldEventSink.recordFieldInt(0, 4, 18, 13, FieldEventSink.READ, staticObserved);
    if (observed != -11 || staticObserved != 42 ||
        FieldEventSink.fieldMetaCount() != 4)
      throw new AssertionError("Direct JNI ABI contract failed");
    return 103;
  }
}
