// Android ART/JVMTI no-template field watch backend (API 28+, debuggable).
// This intentionally does not claim coverage in non-debuggable applications.
// Read events are JVMTI notifications BEFORE the load: primitive values are
// sampled by JNI and can race another thread's write. Write events contain
// JVMTI's proposed value, not a guarantee the store ultimately committed.
// The ART compiler-injection path remains required for exact successful reads.
#include <jni.h>
#include <jvmti.h>
#include <android/log.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#define AW_EXPORT extern "C" __attribute__((visibility("default")))
#define AW_LOG(...) __android_log_print(ANDROID_LOG_INFO,"ARTWATCH_JVMTI",__VA_ARGS__)

namespace {
constexpr uint32_t kCapacity=256;
struct Entry {
  uint32_t kind;
  int64_t location;
  uint64_t bits;
  char field[48];
  char method[48];
};
Entry entries[kCapacity]={};
std::atomic<uint32_t> next_entry{0}, watched{0};
char wanted[192]="Lcom/example/artfieldwatch/JvmtiTarget;";
thread_local bool in_callback=false;

void Dealloc(jvmtiEnv* ti,char* str) {
  if (str!=nullptr) ti->Deallocate(reinterpret_cast<unsigned char*>(str));
}
void Copy(char* out,size_t size,const char* value) {
  if (size==0) return;
  snprintf(out,size,"%s",value==nullptr?"?":value);
}
uint64_t Bits(jvalue v,char signature) {
  uint32_t narrow=0;
  uint64_t wide=0;
  switch(signature) {
    case 'Z': return v.z?1u:0u;
    case 'B': return static_cast<uint64_t>(static_cast<int64_t>(v.b));
    case 'C': return static_cast<uint16_t>(v.c);
    case 'S': return static_cast<uint64_t>(static_cast<int64_t>(v.s));
    case 'I': return static_cast<uint64_t>(static_cast<int64_t>(v.i));
    case 'J': return static_cast<uint64_t>(v.j);
    case 'F': memcpy(&narrow,&v.f,sizeof(narrow));return narrow;
    case 'D': memcpy(&wide,&v.d,sizeof(wide));return wide;
    default: return 0; // Reference values are never dereferenced/published.
  }
}
void Record(jvmtiEnv* ti,jmethodID method,jlocation location,jclass declaring,
            jfieldID field,uint32_t kind,jvalue value,char signature) {
  if (in_callback) return;
  in_callback=true;
  const uint32_t n=next_entry.fetch_add(1,std::memory_order_relaxed);
  if (n<kCapacity) {
    Entry &e=entries[n];
    char *field_name=nullptr,*method_name=nullptr,*type_sig=nullptr;
    if (ti->GetFieldName(declaring,field,&field_name,&type_sig,nullptr)==JVMTI_ERROR_NONE &&
        ti->GetMethodName(method,&method_name,nullptr,nullptr)==JVMTI_ERROR_NONE) {
      Copy(e.field,sizeof(e.field),field_name);
      Copy(e.method,sizeof(e.method),method_name);
      e.kind=kind;e.location=static_cast<int64_t>(location);
      e.bits=Bits(value,signature);
    }
    Dealloc(ti,field_name);
    Dealloc(ti,type_sig);
    Dealloc(ti,method_name);
  }
  in_callback=false;
}
void JNICALL OnWrite(jvmtiEnv* ti,JNIEnv*,jthread,jmethodID method,jlocation location,
                     jclass klass,jobject,jfieldID field,char signature,jvalue new_value) {
  Record(ti,method,location,klass,field,2u,new_value,signature);
}
void JNICALL OnRead(jvmtiEnv* ti,JNIEnv* env,jthread,jmethodID method,jlocation location,
                    jclass klass,jobject object,jfieldID field) {
  if (in_callback) return;
  char* name=nullptr,*sig=nullptr;
  if (ti->GetFieldName(klass,field,&name,&sig,nullptr)!=JVMTI_ERROR_NONE) return;
  const char type=sig!=nullptr?sig[0]:'?';
  Dealloc(ti,name);Dealloc(ti,sig);
  // JNI sampling is only a best-effort value demonstration. The JVMTI read
  // callback has no exact value parameter and cannot prove race-free reads.
  // Prevent JNI Get*Field from recursively triggering another field callback.
  in_callback=true;
  jvalue value={};
  switch(type) {
    case 'I':
      value.i=object?env->GetIntField(object,field):env->GetStaticIntField(klass,field);
      break;
    case 'J':
      value.j=object?env->GetLongField(object,field):env->GetStaticLongField(klass,field);
      break;
    case 'Z':
      value.z=object?env->GetBooleanField(object,field):env->GetStaticBooleanField(klass,field);
      break;
    default: in_callback=false;return;
  }
  if (env->ExceptionCheck()) {env->ExceptionClear();in_callback=false;return;}
  in_callback=false;
  Record(ti,method,location,klass,field,1u,value,type);
}
void Watch(jvmtiEnv* ti,JNIEnv* env,jclass klass) {
  char* signature=nullptr;
  if (ti->GetClassSignature(klass,&signature,nullptr)!=JVMTI_ERROR_NONE) return;
  const bool match=(signature!=nullptr &&
                    strncmp(signature,wanted,strlen(wanted))==0);
  Dealloc(ti,signature);
  if (!match) return;
  jint count=0;jfieldID* fields=nullptr;
  if (ti->GetClassFields(klass,&count,&fields)!=JVMTI_ERROR_NONE) return;
  for(jint i=0;i<count;i++) {
    jvmtiError a=ti->SetFieldAccessWatch(klass,fields[i]);
    jvmtiError b=ti->SetFieldModificationWatch(klass,fields[i]);
    if (a==JVMTI_ERROR_NONE && b==JVMTI_ERROR_NONE)
      watched.fetch_add(1,std::memory_order_relaxed);
  }
  if(fields!=nullptr)ti->Deallocate(reinterpret_cast<unsigned char*>(fields));
  AW_LOG("WATCH_REGISTERED fields=%u",watched.load());
  (void)env;
}
void JNICALL OnClassPrepare(jvmtiEnv* ti,JNIEnv* env,jthread,jclass klass) {
  Watch(ti,env,klass);
}
} // namespace

AW_EXPORT jint Agent_OnAttach(JavaVM* vm,char* options,void*) {
  jvmtiEnv* ti=nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&ti),JVMTI_VERSION_1_2)!=JNI_OK ||
      ti==nullptr) {
    AW_LOG("ATTACH_FAILED missing JVMTI");
    return JNI_ERR;
  }
  if(options && options[0] && strlen(options)<sizeof(wanted))
    Copy(wanted,sizeof(wanted),options);
  jvmtiCapabilities caps={};
  caps.can_generate_field_access_events=1;
  caps.can_generate_field_modification_events=1;
  const jvmtiError cap_err=ti->AddCapabilities(&caps);
  if (cap_err!=JVMTI_ERROR_NONE) {
    AW_LOG("ATTACH_FAILED capabilities=%d",cap_err);
    return JNI_ERR;
  }
  jvmtiEventCallbacks callbacks={};
  callbacks.FieldAccess=OnRead;
  callbacks.FieldModification=OnWrite;
  callbacks.ClassPrepare=OnClassPrepare;
  if(ti->SetEventCallbacks(&callbacks,sizeof(callbacks))!=JVMTI_ERROR_NONE ||
     ti->SetEventNotificationMode(JVMTI_ENABLE,JVMTI_EVENT_FIELD_ACCESS,nullptr)!=JVMTI_ERROR_NONE ||
     ti->SetEventNotificationMode(JVMTI_ENABLE,JVMTI_EVENT_FIELD_MODIFICATION,nullptr)!=JVMTI_ERROR_NONE ||
     ti->SetEventNotificationMode(JVMTI_ENABLE,JVMTI_EVENT_CLASS_PREPARE,nullptr)!=JVMTI_ERROR_NONE) {
    AW_LOG("ATTACH_FAILED callbacks");
    return JNI_ERR;
  }
  JNIEnv* env=nullptr;
  if(vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6)==JNI_OK &&
     env!=nullptr) {
    jint count=0;jclass* classes=nullptr;
    if(ti->GetLoadedClasses(&count,&classes)==JVMTI_ERROR_NONE) {
      for(jint i=0;i<count;i++) Watch(ti,env,classes[i]);
      if(classes)ti->Deallocate(reinterpret_cast<unsigned char*>(classes));
    }
  }
  AW_LOG("ATTACHED target=%s watched=%u",wanted,watched.load());
  return JNI_OK;
}
AW_EXPORT int artwatch_jvmti_snapshot(char* out,uint32_t length) {
  if(!out||length<100) return 0;
  const uint32_t total=next_entry.load(std::memory_order_acquire);
  const uint32_t count=total<kCapacity?total:kCapacity;
  size_t used=0;
  int n=snprintf(out,length,"{\"total\":%u,\"watched\":%u,\"events\":[",
                 total,watched.load(std::memory_order_acquire));
  if(n<0||static_cast<size_t>(n)>=length)return 0;
  used+=static_cast<size_t>(n);
  for(uint32_t i=0;i<count;i++) {
    const Entry& e=entries[i];
    n=snprintf(out+used,length-used,
      "%s{\"kind\":%u,\"location\":%lld,\"field\":\"%s\","
      "\"method\":\"%s\",\"valueBits\":\"0x%016llx\"}",
      i?",":"",e.kind,static_cast<long long>(e.location),e.field,e.method,
      static_cast<unsigned long long>(e.bits));
    if(n<0||static_cast<size_t>(n)>=length-used)return 0;
    used+=static_cast<size_t>(n);
  }
  if(used+3>length)return 0;
  out[used++]=']';out[used++]='}';out[used]=0;
  return 1;
}
