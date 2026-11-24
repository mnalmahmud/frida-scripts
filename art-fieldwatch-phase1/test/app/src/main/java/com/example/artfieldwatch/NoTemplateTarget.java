package com.example.artfieldwatch;

/** Pure Java workload, with no recorder or native dependency. */
public final class NoTemplateTarget {
  private int value;
  private int other;
  private float floating;

  public static void writeInstance(NoTemplateTarget receiver, int x) {
    receiver.value = x;
  }

  public static int readInstance(NoTemplateTarget receiver) {
    return receiver.value;
  }

  public static void writeInstanceFloat(NoTemplateTarget receiver, float value) {
    receiver.floating = value;
  }

  public static float readInstanceFloat(NoTemplateTarget receiver) {
    return receiver.floating;
  }

  // Non-leaf DEX method: 2 field writes and 2 reads with intervening
  // identity invokes; not instrumented by Java sink calls.
  private static NoTemplateTarget identity(NoTemplateTarget target) {
    return target;
  }

  public static int complexStep(NoTemplateTarget receiver, int value) {
    receiver.value = value;
    int a = identity(receiver).value;
    receiver.other = value + 1;
    int b = identity(receiver).other;
    return a + b;
  }

  // Two writes and two reads of the *same* field inside one method.
  // The runtime must report two separate DEX PCs for each opcode/field ID.
  public static int repeatedStep(NoTemplateTarget receiver, int value) {
    receiver.value = value;
    int first = identity(receiver).value;
    receiver.value = value + 2;
    int second = identity(receiver).value;
    return first + second;
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
      if (complexStep(receiver, instance) != 2 * instance + 1)
        throw new AssertionError("No-template non-leaf mismatch at " + i);
      if (repeatedStep(receiver, instance) != 2 * instance + 2)
        throw new AssertionError("Repeated DEX field site mismatch at " + i);
      // Exact raw IEEE754 payloads (including -0 and a noncanonical NaN).
      int floatBits = (i & 1) == 0 ? 0x80000000 : 0x7fc01234;
      int staticFloatBits = (i & 1) == 0 ? 0x00000001 : 0xff800000;
      writeInstanceFloat(receiver, Float.intBitsToFloat(floatBits));
      NoTemplateStaticState.writeStaticFloat(Float.intBitsToFloat(staticFloatBits));
      if (Float.floatToRawIntBits(readInstanceFloat(receiver)) != floatBits ||
          Float.floatToRawIntBits(NoTemplateStaticState.readStaticFloat()) != staticFloatBits)
        throw new AssertionError("Raw float field payload mismatch at " + i);
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
  private static float floating;
  static void writeStatic(int x) { shared = x; }
  static int readStatic() { return shared; }
  static void writeStaticFloat(float value) { floating = value; }
  static float readStaticFloat() { return floating; }
}
