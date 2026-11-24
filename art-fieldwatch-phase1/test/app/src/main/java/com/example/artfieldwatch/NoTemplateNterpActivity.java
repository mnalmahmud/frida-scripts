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
    // Frida first attaches and validates the stock ART binary. Only an
    // independent second start intent triggers this cold field workload.
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
