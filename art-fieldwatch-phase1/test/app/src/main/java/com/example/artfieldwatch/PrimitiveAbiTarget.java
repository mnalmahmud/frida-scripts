package com.example.artfieldwatch;

/** Wide/narrow primitive transport verification, separate from ART injection. */
public final class PrimitiveAbiTarget {
  private long wide;
  private static float f32;
  private double f64;

  public static int exercise() {
    PrimitiveAbiTarget target = new PrimitiveAbiTarget();
    final long expected = -0x102030405060708L;
    target.wide = expected;
    FieldEventSink.recordFieldLong(0,5,21,2,FieldEventSink.WRITE,expected);
    long observed = target.wide;
    FieldEventSink.recordFieldLong(0,5,21,4,FieldEventSink.READ,observed);
    f32 = -0.0f;
    FieldEventSink.recordFieldFloat(0,5,22,6,FieldEventSink.WRITE,-0.0f);
    float f = f32;
    FieldEventSink.recordFieldFloat(0,5,22,8,FieldEventSink.READ,f);
    target.f64 = -0.0d;
    FieldEventSink.recordFieldDouble(0,5,23,10,FieldEventSink.WRITE,-0.0d);
    double d = target.f64;
    FieldEventSink.recordFieldDouble(0,5,23,12,FieldEventSink.READ,d);

    FieldEventSink.recordFieldNarrow(0,6,24,14,FieldEventSink.READ,1,1);
    FieldEventSink.recordFieldNarrow(0,6,25,16,FieldEventSink.WRITE,2,-128);
    FieldEventSink.recordFieldNarrow(0,6,26,18,FieldEventSink.READ,3,0xd7ff);
    FieldEventSink.recordFieldNarrow(0,6,27,20,FieldEventSink.WRITE,4,-32768);
    if (observed!=expected || Float.floatToRawIntBits(f)!=0x80000000 ||
        Double.doubleToRawLongBits(d)!=Long.MIN_VALUE ||
        FieldEventSink.fieldMetaCount()!=14)
      throw new AssertionError("Primitive field-event JNI transport failed");
    return 61;
  }
}
