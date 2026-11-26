package com.example.artfieldwatch;
public final class FieldWatchTarget {
 private int counter;
 private volatile long published;
 private static Object lastObject;
 private static volatile int checksum;
 private int readCounter() { return counter; }
 private void writeCounter(int x) { counter = x; }
 private long readPublished() { return published; }
 private void writePublished(long x) { published = x; }
 public static int exercise(int iterations) {
  FieldWatchTarget target = new FieldWatchTarget();
  int sum = 0;
  for (int i = 0; i < iterations; i++) {
   target.writeCounter(i);
   sum += target.readCounter();
   target.writePublished(sum);
   sum += (int) target.readPublished();
   lastObject = target;
   if (lastObject == null) throw new AssertionError();
  }
  checksum = sum;
  return checksum;
 }
}
