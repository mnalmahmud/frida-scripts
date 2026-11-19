#!/usr/bin/env python3
"""Frida + Android fixture integration smoke, NOT field-hook coverage."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import frida

BASE = Path(__file__).resolve().parents[1]
LOG_DIR = Path(os.environ.get('ARTWATCH_LOG_DIR','/tmp/artwatch-logs'))
LOG_DIR.mkdir(parents=True,exist_ok=True)
messages, errors = [], []

def record(kind,content):
    messages.append({'kind':kind,'text':str(content)})
    print(f'[{kind}] {content}',flush=True)

def on_message(message,data):
    if message.get('type') == 'error':
        errors.append(message.get('stack') or message.get('description') or str(message))
        record('error',errors[-1])
    else:
        record('frida',json.dumps(message,sort_keys=True))

def main():
    device = frida.get_usb_device(timeout=30)
    record('host','frida-device='+device.name)
    pid = device.spawn(['com.example.artfieldwatch'])
    record('host','spawned-pid='+str(pid))
    session = device.attach(pid)
    try:
        script = session.create_script((BASE/'jit-boundary-probe.js').read_text())
        script.on('message',on_message)
        script.set_log_handler(lambda level, line: record('console-'+level, line))
        script.load()
        device.resume(pid)
        time.sleep(20)
    finally:
        try: session.detach()
        except frida.InvalidOperationError: pass
    logs = subprocess.run(['adb','logcat','-d','-s','ARTWATCH_CI:I','*:S'],
      capture_output=True,text=True,check=False)
    (LOG_DIR/'logcat.txt').write_text(logs.stdout+logs.stderr)
    (LOG_DIR/'frida-messages.json').write_text(json.dumps(messages,indent=2))
    text = '\n'.join(m['text'] for m in messages)
    if 'module=libart' not in text: raise AssertionError('libart not discovered')
    if 'arch=' not in text: raise AssertionError('No Frida process header')
    if errors: raise AssertionError('Frida errors: '+'; '.join(errors))
    if 'WARMUP_FAILED' in logs.stdout or 'WARMUP_DONE' not in logs.stdout:
        raise AssertionError('APK fixture warmup failed or timed out')
    if os.environ.get('ARTWATCH_REQUIRE_JIT') == '1':
        if 'Attached compilation observer' not in text:
            raise AssertionError('No native JIT hook installed')
        if 'JIT success' not in text:
            raise AssertionError('No JIT compile observed')
    record('host','PASS: Frida attach + ART discovery + fixture warmup')

if __name__ == '__main__':
    try: main()
    except Exception as e:
        record('host','FAIL: '+repr(e))
        (LOG_DIR/'frida-messages.json').write_text(json.dumps(messages,indent=2))
        sys.exit(1)
