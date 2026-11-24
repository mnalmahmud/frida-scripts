package com.example.artfieldwatch;

/** Pure Java workload, with no recorder or native dependency. */
public final class NoTemplateTarget {
  private int value;

  public static void writeInstance(NoTemplateTarget receiver, int x) {
    receiver.value = x;
  }

  public static int readInstance(NoTemplateTarget receiver) {
    return receiver.value;
  }

  public static int exercise() {
    NoTemplateTarget receiver = new NoTemplateTarget();
    int checksum = 0;
    for (int i = 0; i < 128; i++) {
      int instance = 7 + 3 * i;
      int shared = -11 - 5 * i;
      writeInstance(receiver, instance);
      NoTemplateStaticState.writeStatic(shared);
      int observedInstance = readInstance(receiver);
      int observedStatic = NoTemplateStaticState.readStatic();
      if (observedInstance != instance || observedStatic != shared) {
        throw new AssertionError("No-template value mismatch at " + i);
      }
      checksum += observedInstance + observedStatic;
    }
    int failed = 0;
    try { writeInstance(null, 777); }
    catch (NullPointerException expected) { failed++; }
    try { readInstance(null); }
    catch (NullPointerException expected) { failed++; }
    if (failed != 2 || checksum != -16768) {
      throw new AssertionError("No-template checksum or null failure mismatch");
    }
    return checksum;
  }
}

/** A second declaring class, independent of the instance field. */
final class NoTemplateStaticState {
  private static int shared;
  static void writeStatic(int x) { shared = x; }
  static int readStatic() { return shared; }
}
