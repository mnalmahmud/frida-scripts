package com.example.artfieldwatch;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;

/** Isolated stock-ART interpreter experiment. No field event templates. */
public final class NoTemplateNterpActivity extends Activity {
  private boolean started = false;

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
    // Frida attaches/validates ART before the second launch starts measurement.
    Log.i("ARTWATCH_NTERP_LAB", "NTERP_LAB_IDLE");
  }

  @Override protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    if (!intent.getBooleanExtra("run", false) || started) return;
    started = true;
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
