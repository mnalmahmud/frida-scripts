package com.example.artfieldwatch;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;
import java.util.concurrent.CountDownLatch;

/** Isolated stock-ART interpreter experiment. No field event templates. */
public final class NoTemplateNterpActivity extends Activity {
  private boolean started = false;
  private volatile CountDownLatch parallelGate;

  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED debuggable");
      finish();
      return;
    }
    // Resolve and initialize the second declaring class before the host arms
    // nterp. The measured phase then exercises both fields through their
    // normal hot interpreter paths, without mixing class-initialization
    // dispatch into the 512-event test.
    int initial = NoTemplateStaticState.readStatic();
    if (initial != 0) {
      Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED unexpected initial static value");
      finish();
      return;
    }
    // Preload Float helper code before arming interpreter field breakpoints.
    if (Float.floatToRawIntBits(Float.intBitsToFloat(0x80000000)) != 0x80000000 ||
        Float.floatToRawIntBits(NoTemplateStaticState.readStaticFloat()) != 0) {
      Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED float initialization");
      finish();
      return;
    }
    // Ensure static wide field initialization and Double helper linkage
    // occur before the opcode breakpoint family is armed.
    if (NoTemplateStaticState.readStaticLong() != 0L ||
        Double.doubleToRawLongBits(NoTemplateStaticState.readStaticDouble()) != 0L ||
        Double.doubleToRawLongBits(Double.longBitsToDouble(0x8000000000000000L))
          != 0x8000000000000000L) {
      Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED wide initialization");
      finish();
      return;
    }
    // Frida attaches/validates ART before the second launch starts measurement.
    Log.i("ARTWATCH_NTERP_LAB", "NTERP_LAB_IDLE");
  }

  @Override protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    // The host releases the two workers only after Stalker confirms
    // that both named threads are followed. This avoids a startup race
    // between Thread.run() and the instrumentation observer.
    if (intent.getBooleanExtra("parallelGo", false)) {
      CountDownLatch gate = parallelGate;
      if (gate != null) gate.countDown();
      return;
    }
    final boolean parallel = intent.getBooleanExtra("parallel", false);
    if ((!intent.getBooleanExtra("run", false) && !parallel) || started) return;
    started = true;
    if (parallel) {
      parallelGate = new CountDownLatch(1);
      new Thread(() -> {
        try {
          CountDownLatch ready = new CountDownLatch(2);
          Thread[] workers = new Thread[2];
          int[] results = new int[2];
          Throwable[] errors = new Throwable[2];
          for (int i = 0; i < 2; i++) {
            final int worker = i;
            workers[i] = new Thread(() -> {
              try {
                ready.countDown();
                parallelGate.await();
                results[worker] =
                    NoTemplateTarget.exerciseParallelInstance(worker);
              } catch (Throwable e) {
                errors[worker] = e;
              }
            }, "NterpFieldProbe");
            workers[i].start();
          }
          ready.await();
          Log.i("ARTWATCH_NTERP_LAB", "NTERP_LAB_PARALLEL_READY");
          for (Thread worker : workers) worker.join();
          if (errors[0] != null) throw new AssertionError(errors[0]);
          if (errors[1] != null) throw new AssertionError(errors[1]);
          int checksum = results[0] + results[1];
          if (checksum != 4116352) throw new AssertionError("Parallel checksum");
          Log.i("ARTWATCH_NTERP_LAB",
                "NTERP_LAB_PARALLEL_DONE checks=256 checksum=" + checksum);
        } catch (Throwable e) {
          Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED", e);
        }
      }, "NterpFieldCoordinator").start();
      return;
    }
    new Thread(() -> {
      try {
        int checksum = NoTemplateTarget.exercise();
        Log.i("ARTWATCH_NTERP_LAB",
              "NTERP_LAB_DONE checksum=" + checksum + " nullChecks=2");
      } catch (Throwable e) {
        Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED", e);
      }
    }, "NterpFieldProbe").start();
  }
}
