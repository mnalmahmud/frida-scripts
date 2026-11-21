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
  public static native void reset();
}
