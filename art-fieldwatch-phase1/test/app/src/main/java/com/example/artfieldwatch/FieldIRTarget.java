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
