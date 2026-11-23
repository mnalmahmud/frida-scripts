package com.example.artfieldwatch;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public final class MainActivity extends Activity {
 @Override
 protected void onCreate(Bundle state) {
  super.onCreate(state);
  TextView label = new TextView(this);
  label.setText("ART Fieldwatch: field access warmup");
  setContentView(label);
  final boolean appDebuggable =
    (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
  Log.i("ARTWATCH_CI","APP_DEBUGGABLE=" + appDebuggable);
  // Load the native P1 companion from the APK on the API33 emulator.
  // The Frida agent only looks up the already-loaded module and never
  // tries to mmap a shared library from /data/local/tmp.
  if (android.os.Build.VERSION.SDK_INT == 33) {
   try {
    System.loadLibrary("artwatch_shadow");
    System.loadLibrary("artwatch_events");
    Log.i("ARTWATCH_CI","SHADOW_LIB_LOADED=true");
    Log.i("ARTWATCH_CI","EVENT_LIB_LOADED=true");
   } catch (UnsatisfiedLinkError e) {
    Log.e("ARTWATCH_CI","SHADOW_LIB_LOAD_FAILED",e);
   }
  }
  new Thread(() -> {
   long accumulator = 0;
   try {
    for (int i = 0; i < 40; i++)
     accumulator += FieldWatchTarget.exercise(100000);
    accumulator += FieldIRTarget.warmup(150000);
    // Give the non-debuggable app enough hot calls for optimized compilation.
    // No deoptimization or reflective compiler calls are used.
    if (!appDebuggable) {
     // Distinct methods generate multiple natural JIT compilation
     // opportunities. Brief pauses allow the worker to drain its queue.
     // No deoptimization or hidden ART APIs are invoked.
     for (int stage = 0; stage < 5; stage++) {
      accumulator += FieldIRTarget.warmup(300000);
      accumulator += FieldIRTarget.exerciseOverwrites(300000);
      accumulator += FieldIRTarget.exerciseAlternating(300000);
      Log.i("ARTWATCH_CI", "LSE_STAGE_DONE=" + stage);
      Thread.sleep(400);
     }
    }
    // Executed from the real app worker; the host Frida client drains
    // the native records after this completion marker.
    if (android.os.Build.VERSION.SDK_INT == 33) {
     int carrierChecksum = FieldIRTarget.exerciseP3TemplateCarrier(appDebuggable);
     Log.i("ARTWATCH_CI","P3_TEMPLATE_DONE count=" +
           FieldEventSink.eventCount() + " checksum=" +
           carrierChecksum + " nullCheck=true injected=" +
           FieldEventSink.p3Enabled());
     accumulator += carrierChecksum;
     int canaryChecksum = FieldIRTarget.exerciseP3UninstrumentedCanary();
     Log.i("ARTWATCH_CI","P3_CANARY_DONE count=0 checksum=" +
           canaryChecksum + " nullCheck=true");
     accumulator += canaryChecksum;
     int runtimeChecksum = FieldIRTarget.exerciseRuntimeEvents();
     Log.i("ARTWATCH_CI","RUNTIME_EVENTS_DONE count=256 checksum=" +
           runtimeChecksum + " nullCheck=true");
     accumulator += runtimeChecksum;
     // Explicit transport-only ABI check. NOT a compiler-injection result.
     int abiChecksum = DirectAbiTarget.exercise();
     Log.i("ARTWATCH_CI","DIRECT_ABI_DONE count=" +
           FieldEventSink.fieldMetaCount() + " checksum=" + abiChecksum);
     accumulator += abiChecksum;
    }
    Log.i("ARTWATCH_CI","WARMUP_DONE checksum=" + accumulator);
   } catch (Throwable t) {
    Log.e("ARTWATCH_CI","WARMUP_FAILED",t);
   }
  }, "FieldwatchWarmup").start();
 }
}
