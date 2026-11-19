package com.example.artfieldwatch;

/** Deliberately tiny DEX iget/iput test for compiler IR experiments. */
public final class FieldIRTarget {
  private int value;

  public int test(int x) {
    value = x;
    return value;
  }

  public static int warmup(int iterations) {
    FieldIRTarget target = new FieldIRTarget();
    int observed = 0;
    for (int i = 0; i < iterations; i++) {
      if (target.test(i) != i) {
        throw new AssertionError("FieldIRTarget read/write mismatch at " + i);
      }
      observed++;
    }
    return observed;
  }
}
