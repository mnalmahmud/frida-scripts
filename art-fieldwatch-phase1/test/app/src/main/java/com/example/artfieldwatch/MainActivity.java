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
  new Thread(() -> {
   long accumulator = 0;
   try {
    for (int i = 0; i < 40; i++)
     accumulator += FieldWatchTarget.exercise(100000);
    accumulator += FieldIRTarget.warmup(150000);
    // Give the non-debuggable app enough hot calls for optimized compilation.
    // No deoptimization or reflective compiler calls are used.
    if (!appDebuggable) accumulator += FieldIRTarget.warmup(1200000);
    Log.i("ARTWATCH_CI","WARMUP_DONE checksum=" + accumulator);
   } catch (Throwable t) {
    Log.e("ARTWATCH_CI","WARMUP_FAILED",t);
   }
  }, "FieldwatchWarmup").start();
 }
}
