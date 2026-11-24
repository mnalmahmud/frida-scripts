package com.example.artfieldwatch;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.util.Log;

/** Isolated synthetic workload for a source-built ART laboratory image. */
public final class NoTemplateLabActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      Log.e("ARTWATCH_LAB", "NO_TEMPLATE_LAB_FAILED debuggable");
      finish();
      return;
    }
    new Thread(() -> {
      try {
        int checksum = NoTemplateTarget.exercise();
        Log.i("ARTWATCH_LAB", "NO_TEMPLATE_LAB_DONE checksum=" + checksum + " nullChecks=2");
      } catch (Throwable failure) {
        Log.e("ARTWATCH_LAB", "NO_TEMPLATE_LAB_FAILED", failure);
      }
    }, "ArtwatchLab").start();
  }
}
