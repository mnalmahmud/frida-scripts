package com.example.artfieldwatch;

/** Pure Java workload, with no recorder or native dependency. */
public final class NoTemplateTarget {
  private int value;
  private int other;
  private float floating;
  private long large;
  private double precise;
  private boolean flag;
  private byte tiny;
  private char glyph;
  private short small;
  private Object reference;

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

  public static void writeInstanceLong(NoTemplateTarget receiver, long value) {
    receiver.large = value;
  }

  public static long readInstanceLong(NoTemplateTarget receiver) {
    return receiver.large;
  }

  public static void writeInstanceDouble(NoTemplateTarget receiver, double value) {
    receiver.precise = value;
  }

  public static double readInstanceDouble(NoTemplateTarget receiver) {
    return receiver.precise;
  }

  public static void writeInstanceBoolean(NoTemplateTarget receiver, boolean value) {
    receiver.flag = value;
  }
  public static boolean readInstanceBoolean(NoTemplateTarget receiver) {
    return receiver.flag;
  }
  public static void writeInstanceByte(NoTemplateTarget receiver, byte value) {
    receiver.tiny = value;
  }
  public static byte readInstanceByte(NoTemplateTarget receiver) {
    return receiver.tiny;
  }
  public static void writeInstanceChar(NoTemplateTarget receiver, char value) {
    receiver.glyph = value;
  }
  public static char readInstanceChar(NoTemplateTarget receiver) {
    return receiver.glyph;
  }
  public static void writeInstanceShort(NoTemplateTarget receiver, short value) {
    receiver.small = value;
  }
  public static short readInstanceShort(NoTemplateTarget receiver) {
    return receiver.small;
  }

  public static void writeInstanceObject(NoTemplateTarget receiver, Object value) {
    receiver.reference = value;
  }
  public static Object readInstanceObject(NoTemplateTarget receiver) {
    return receiver.reference;
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

  // Concurrent worker fixture. Both workers call the same two real
  // field-bearing DEX leaf methods, but write separate receiver objects.
  // Their disjoint value ranges permit an exact per-thread event oracle
  // without depending on global interleaving order.
  public static int exerciseParallelInstance(int worker) {
    NoTemplateTarget receiver = new NoTemplateTarget();
    int checksum = 0;
    for (int i = 0; i < 128; i++) {
      int value = 10000 * (worker + 1) + 17 * i;
      writeInstance(receiver, value);
      int observed = readInstance(receiver);
      if (observed != value)
        throw new AssertionError("Parallel field mismatch worker=" +
            worker + " iteration=" + i);
      checksum += observed;
    }
    return checksum;
  }

  public static int exercise() {
    NoTemplateTarget receiver = new NoTemplateTarget();
    int checksum = 0;
    // Strongly rooted Java locals; the emitted register snapshots are NOT
    // durable references and are never dereferenced from Frida.
    Object instanceReference = new Object();
    Object staticReference = new Object();
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
      // 64-bit fields use iget-wide/iput-wide/sget-wide/sput-wide.
      // Mix the high and low halves of long values independently.
      long instanceLong = 0x8123456789abcdefL ^ (i * 0x100000001L);
      long staticLong = 0xfedcba9876543210L - i * 0x0102030405060708L;
      writeInstanceLong(receiver, instanceLong);
      NoTemplateStaticState.writeStaticLong(staticLong);
      if (readInstanceLong(receiver) != instanceLong ||
          NoTemplateStaticState.readStaticLong() != staticLong)
        throw new AssertionError("Long field mismatch at " + i);
      long doubleBits = (i & 1) == 0
          ? 0x8000000000000000L : 0x7ff8000000001234L;
      long staticDoubleBits = (i & 1) == 0
          ? 0x0000000000000001L : 0xfff0000000000000L;
      writeInstanceDouble(receiver, Double.longBitsToDouble(doubleBits));
      NoTemplateStaticState.writeStaticDouble(Double.longBitsToDouble(staticDoubleBits));
      if (Double.doubleToRawLongBits(readInstanceDouble(receiver)) != doubleBits ||
          Double.doubleToRawLongBits(NoTemplateStaticState.readStaticDouble()) != staticDoubleBits)
        throw new AssertionError("Double field raw bits mismatch at " + i);
      boolean instanceBoolean = (i & 1) == 0;
      boolean staticBoolean = i % 3 == 0;
      writeInstanceBoolean(receiver, instanceBoolean);
      NoTemplateStaticState.writeStaticBoolean(staticBoolean);
      if (readInstanceBoolean(receiver) != instanceBoolean ||
          NoTemplateStaticState.readStaticBoolean() != staticBoolean)
        throw new AssertionError("Boolean field mismatch at " + i);
      byte instanceByte = (byte)(i * 7 - 129);
      byte staticByte = (byte)(127 - i * 5);
      writeInstanceByte(receiver, instanceByte);
      NoTemplateStaticState.writeStaticByte(staticByte);
      if (readInstanceByte(receiver) != instanceByte ||
          NoTemplateStaticState.readStaticByte() != staticByte)
        throw new AssertionError("Signed byte field mismatch at " + i);
      char instanceChar = (char)(0x8000 + i * 257);
      char staticChar = (char)(0xffff - i * 263);
      writeInstanceChar(receiver, instanceChar);
      NoTemplateStaticState.writeStaticChar(staticChar);
      if (readInstanceChar(receiver) != instanceChar ||
          NoTemplateStaticState.readStaticChar() != staticChar)
        throw new AssertionError("Unsigned char field mismatch at " + i);
      short instanceShort = (short)(0x8000 + i * 263);
      short staticShort = (short)(0x7fff - i * 311);
      writeInstanceShort(receiver, instanceShort);
      NoTemplateStaticState.writeStaticShort(staticShort);
      if (readInstanceShort(receiver) != instanceShort ||
          NoTemplateStaticState.readStaticShort() != staticShort)
        throw new AssertionError("Signed short field mismatch at " + i);
      Object expectedInstanceObject = (i & 1) == 0 ? instanceReference : null;
      Object expectedStaticObject = (i & 1) == 0 ? null : staticReference;
      writeInstanceObject(receiver, expectedInstanceObject);
      NoTemplateStaticState.writeStaticObject(expectedStaticObject);
      if (readInstanceObject(receiver) != expectedInstanceObject ||
          NoTemplateStaticState.readStaticObject() != expectedStaticObject)
        throw new AssertionError("Reference field mismatch at " + i);
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
  private static long sharedLong;
  private static double sharedDouble;
  private static boolean sharedBoolean;
  private static byte sharedByte;
  private static char sharedChar;
  private static short sharedShort;
  private static Object sharedObject;
  static void writeStatic(int x) { shared = x; }
  static int readStatic() { return shared; }
  static void writeStaticFloat(float value) { floating = value; }
  static float readStaticFloat() { return floating; }
  static void writeStaticLong(long value) { sharedLong = value; }
  static long readStaticLong() { return sharedLong; }
  static void writeStaticDouble(double value) { sharedDouble = value; }
  static double readStaticDouble() { return sharedDouble; }
  static void writeStaticBoolean(boolean value) { sharedBoolean = value; }
  static boolean readStaticBoolean() { return sharedBoolean; }
  static void writeStaticByte(byte value) { sharedByte = value; }
  static byte readStaticByte() { return sharedByte; }
  static void writeStaticChar(char value) { sharedChar = value; }
  static char readStaticChar() { return sharedChar; }
  static void writeStaticShort(short value) { sharedShort = value; }
  static short readStaticShort() { return sharedShort; }
  static void writeStaticObject(Object value) { sharedObject = value; }
  static Object readStaticObject() { return sharedObject; }
}
