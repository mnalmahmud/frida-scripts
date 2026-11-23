package com.example.artfieldwatch;

/**
 * Controlled prototype of the future side-effecting compiler event call.
 * recordInt() is native, externally observable, and deliberately invoked
 * by fixture bytecode. It is NOT yet inserted into ART HGraph.
 */
public final class FieldEventSink {
  private FieldEventSink() {}

  public static final int READ = 1;
  public static final int WRITE = 2;
  public static final int SITE_WRITE_VALUE = 9001;
  public static final int SITE_READ_VALUE = 9002;

  public static native void recordInt(int site, int kind, int value);
  public static native void recordFieldInt(int dexId, int methodId,
      int fieldId, int dexPc, int kind, int value);
  // JNI inputs carry original field values; raw float/double bits are
  // preserved as unsigned hexadecimal fields in the event transport.
  public static native void recordFieldLong(int dexId,int methodId,
      int fieldId,int dexPc,int kind,long value);
  public static native void recordFieldFloat(int dexId,int methodId,
      int fieldId,int dexPc,int kind,float value);
  public static native void recordFieldDouble(int dexId,int methodId,
      int fieldId,int dexPc,int kind,double value);
  public static native void recordFieldNarrow(int dexId,int methodId,
      int fieldId,int dexPc,int kind,int type,int value);
  public static native void resetFieldMeta();
  public static native int fieldMetaCount();
  public static native void reset();
  public static native int eventCount();
  public static native boolean p3Enabled();
  public static native boolean p3Verified();
}
