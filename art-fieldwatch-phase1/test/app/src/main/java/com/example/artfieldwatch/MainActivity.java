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
  new Thread(() -> {
   long accumulator = 0;
   try {
    for (int i = 0; i < 40; i++)
     accumulator += FieldWatchTarget.exercise(100000);
    Log.i("ARTWATCH_CI","WARMUP_DONE checksum=" + accumulator);
   } catch (Throwable t) {
    Log.e("ARTWATCH_CI","WARMUP_FAILED",t);
   }
  }, "FieldwatchWarmup").start();
 }
}
