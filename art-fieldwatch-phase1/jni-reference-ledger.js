'use strict';
// Strict opt-in ART/JNI GC-root identity experiment, API33 x86_64 only.
// Run ONLY on a Java thread executing verified nterp field opcodes.
// Unlike JNI NewGlobalRef(jobject), JNIEnvExt::NewLocalRef takes an
// art::mirror::Object* and is a PRIVATE ART ABI. It must be gated by the
// matching libart Build ID; never feed raw heap pointers to JNI methods.
// The reference is immediately converted to a JNI weak global before any
// object identity is exported. Weak handles do not pin Java objects.
globalThis.__artwatchMakeReferenceLedger=function(libart,maxObjects) {
  const expected='c8b6a2df9893030c07b3b96dc24a7d30';
  if (Process.arch!=='x64' || Process.pointerSize!==8 ||
      libart.name!=='libart.so' || maxObjects<1 || maxObjects>2048)
    throw new Error('Unsupported reference-root bridge ABI');
  // Caller has already verified the *loaded* ELF Build ID at install().
  const factory=libart.findExportByName('JNI_GetCreatedJavaVMs');
  const newLocalSym=libart.findExportByName(
    '_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE');
  if (factory===null || newLocalSym===null)
    throw new Error('Missing exact ART JNIEnvExt root bridge exports');
  const getVMs=new NativeFunction(factory,'int',['pointer','int','pointer']);
  const vmBuf=Memory.alloc(Process.pointerSize);
  const nBuf=Memory.alloc(4);
  if (getVMs(vmBuf,1,nBuf)!==0 || nBuf.readS32()!==1)
    throw new Error('Expected exactly one running JavaVM');
  const vm=vmBuf.readPointer();
  if (vm.isNull()) throw new Error('Null ART JavaVM');
  const invoke=vm.readPointer();
  function invocation(index,ret,args) {
    const fn=invoke.add(index*Process.pointerSize).readPointer();
    if (fn.isNull()) throw new Error('Missing JNI invoke function '+index);
    return new NativeFunction(fn,ret,args);
  }
  const vmGetEnv=invocation(6,'int',['pointer','pointer','int']);
  const vmAttach=invocation(4,'int',['pointer','pointer','pointer']);
  const vmDetach=invocation(5,'int',['pointer']);
  const makeLocal=new NativeFunction(newLocalSym,'pointer',['pointer','pointer']);
  let unique=0,overflow=0;
  const entries=[];
  const JNI_VERSION_1_6=0x00010006;
  function envForThread(canAttach) {
    const out=Memory.alloc(Process.pointerSize);
    let status=vmGetEnv(vm,out,JNI_VERSION_1_6);
    let attached=false;
    if (status!==0 && canAttach) {
      status=vmAttach(vm,out,ptr(0));
      attached=status===0;
    }
    if (status!==0 || out.readPointer().isNull())
      throw new Error('JNIEnv unavailable on managed opcode thread');
    return {env:out.readPointer(),attached};
  }
  function jniFunction(env,index,ret,args) {
    const vtable=env.readPointer();
    const address=vtable.add(index*Process.pointerSize).readPointer();
    if (address.isNull()) throw new Error('Missing JNI vtable entry '+index);
    return new NativeFunction(address,ret,args);
  }
  function observe(hex) {
    if (hex==='0x00000000') return {id:null,stable:true};
    if (!/^0x[0-9a-f]{8}$/i.test(hex))
      throw new Error('Only exact compressed nterp GC roots are accepted');
    const {env}=envForThread(false);
    const makeWeak=jniFunction(env,226,'pointer',['pointer','pointer']);
    const deleteWeak=jniFunction(env,227,'void',['pointer','pointer']);
    const deleteLocal=jniFunction(env,23,'void',['pointer','pointer']);
    const isSame=jniFunction(env,24,'int',['pointer','pointer','pointer']);
    const local=makeLocal(env,ptr(hex));
    if (local.isNull())
      throw new Error('ART JNIEnvExt could not create local object reference');
    try {
      for (let k=entries.length-1;k>=0;k--) {
        const e=entries[k];
        if (isSame(env,e.weak,ptr(0))!==0) {
          deleteWeak(env,e.weak);
          entries.splice(k,1);
          continue;
        }
        if (isSame(env,e.weak,local)!==0)
          return {id:e.id,stable:true};
      }
      if (entries.length>=maxObjects) {
        overflow++;
        throw new Error('GC-stable weak JNI reference table full');
      }
      const weak=makeWeak(env,local);
      if (weak.isNull()) throw new Error('Cannot establish weak JNI root');
      const id='art-ref-'+(++unique);
      entries.push({id,weak});
      return {id,stable:true};
    } finally {
      deleteLocal(env,local);
    }
  }
  function stop() {
    const {env,attached}=envForThread(true);
    try {
      const deleteWeak=jniFunction(env,227,'void',['pointer','pointer']);
      for (const e of entries) deleteWeak(env,e.weak);
      entries.length=0;
    } finally {
      if (attached && vmDetach(vm)!==0)
        throw new Error('Unable to detach JNI cleanup thread');
    }
  }
  function snapshot() {return {active:entries.length,unique,overflow};}
  return {observe,stop,snapshot,expectedBuildId:expected};
};
