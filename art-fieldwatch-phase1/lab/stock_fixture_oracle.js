'use strict';

// Test oracle for the four pure leaf methods in our synthetic APK only.
// This uses the public Java bridge. It is NOT a general field-opcode hook.
Java.perform(function () {
  const ActivityThread = Java.use('android.app.ActivityThread');
  const app = ActivityThread.currentApplication();
  if (app === null ||
      app.getPackageName().toString() !== 'com.example.artfieldwatch' ||
      (app.getApplicationInfo().flags.value & 2) !== 0) {
    throw new Error('Expected the non-debuggable synthetic CI fixture');
  }
  const Instance = Java.use('com.example.artfieldwatch.NoTemplateTarget');
  const StaticState = Java.use('com.example.artfieldwatch.NoTemplateStaticState');
  let sequence = 0;

  function observe(name, value) {
    sequence++;
    if (sequence > 512) throw new Error('Unexpected additional fixture call');
    console.log('ARTWATCH_STOCK_EVENT ' + JSON.stringify({
      seq: sequence, method: name, value: value
    }));
  }

  const wi = Instance.writeInstance.overload(
    'com.example.artfieldwatch.NoTemplateTarget', 'int');
  const ri = Instance.readInstance.overload('com.example.artfieldwatch.NoTemplateTarget');
  const ws = StaticState.writeStatic.overload('int');
  const rs = StaticState.readStatic.overload();
  wi.implementation = function (receiver, value) {
    wi.call(this, receiver, value);
    observe('writeInstance', value);
  };
  ri.implementation = function (receiver) {
    const value = ri.call(this, receiver);
    observe('readInstance', value);
    return value;
  };
  ws.implementation = function (value) {
    ws.call(this, value);
    observe('writeStatic', value);
  };
  rs.implementation = function () {
    const value = rs.call(this);
    observe('readStatic', value);
    return value;
  };
  console.log('ARTWATCH_STOCK_READY');
});
