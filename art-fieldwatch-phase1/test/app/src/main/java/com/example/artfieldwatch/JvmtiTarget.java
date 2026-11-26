package com.example.artfieldwatch;
/** Pure Java field access fixture: no callbacks or sink calls in bytecode. */
public final class JvmtiTarget {
  private int instanceValue;
  private static long staticValue;
  public static int exercise(int count) {
    JvmtiTarget holder=new JvmtiTarget();
    int sum=0;
    for(int i=0;i<count;i++) {
      holder.instanceValue=i*7+1;
      int observed=holder.instanceValue;
      staticValue=(long)observed+1000L;
      long shared=staticValue;
      if(observed!=i*7+1 || shared!=observed+1000L)
        throw new AssertionError("JVMTI field mismatch");
      sum+=observed&1;
    }
    return sum;
  }
}
