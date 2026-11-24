package com.example.artfieldwatch;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;

/** Isolated stock-ART nterp opcode test, without native event templates. */
public final class NoTemplateNterpActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      Log.e("ARTWATCH_NTERP_LAB", "NTERP_LAB_FAILED debuggable");
      finish();
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
