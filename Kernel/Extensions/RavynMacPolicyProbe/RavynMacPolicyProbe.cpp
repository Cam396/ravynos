
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
extern "C" {
#include <sys/kernel_types.h>
#include <security/mac_policy_v80.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/attr.h>
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <libkern/OSAtomic.h>
extern uint64_t proc_uniqueid(proc_t);
extern int proc_pidversion(proc_t);
extern int mac_schedule_telemetry(void);

typedef int (*lab_syscall_filter_fn)(proc_t,int);
typedef int (*lab_kobject_filter_fn)(proc_t,int,int);
struct lab_syscall_filter_callbacks {
 int version;
 lab_syscall_filter_fn const unix_filter_cbfunc;
 lab_syscall_filter_fn const mach_filter_cbfunc;
 lab_kobject_filter_fn const kobj_filter_cbfunc;
};
extern int proc_set_syscall_filter_callbacks(struct lab_syscall_filter_callbacks *);
extern int proc_set_syscall_filter_index(int,int,int);
extern size_t proc_get_syscall_filter_mask_size(int);
extern int proc_set_syscall_filter_mask(proc_t,int,unsigned char *,size_t);

}
class RavynMacPolicyProbe : public IOService {
    OSDeclareDefaultStructors(RavynMacPolicyProbe)
public:
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
};
OSDefineMetaClassAndStructors(RavynMacPolicyProbe, IOService)
static mac_policy_handle_t legacy_handle,modern_handle;
static bool legacy_loaded,modern_loaded;
static int probe_initialized,probe_destroyed;
static struct mac_policy_ops old_ops;
static struct mac_policy_ops_v80 new_ops;
static struct mac_policy_conf old_conf,new_conf;
static void policy_init(struct mac_policy_conf *) { probe_initialized++; }
static void policy_destroy(struct mac_policy_conf *) { probe_destroyed++; }
static bool target(struct proc *p) {
    char name[32]={0};proc_name(proc_pid(p),name,sizeof(name));
    return strcmp(name,"mac-v80-probe")==0;
}
static int legacy_signal(kauth_cred_t,struct proc *p,int signal) {
    if(!target(p))return 0;
    int error=signal==SIGUSR2?EPERM:0;
    IOLog("RAVYN-MACV80_HOOK abi=62 signal=%d error=%d\n",signal,error);
    return error;
}
static int modern_signal(kauth_cred_t,struct proc *p,int signal) {
    if(!target(p))return 0;
    int error=signal==SIGUSR1?EACCES:0;
    IOLog("RAVYN-MACV80_HOOK abi=80 signal=%d error=%d\n",signal,error);
    return error;
}

static int legacy_getattr(kauth_cred_t,struct vnode *,struct label *,struct attrlist *attrs) {
    char name[32]={0};proc_name(proc_selfpid(),name,sizeof(name));if(strcmp(name,"mac-v80-probe")!=0)return 0;
    int error=(attrs->commonattr & ATTR_CMN_FILEID)?EPERM:0;
    IOLog("RAVYN-MACV80_GETATTR abi=62 attrs=%x error=%d\n",attrs->commonattr,error);
    return error;
}
static int modern_getattr(kauth_cred_t,struct vnode *,struct label *,struct attrlist *attrs,uint64_t options) {
    char name[32]={0};proc_name(proc_selfpid(),name,sizeof(name));if(strcmp(name,"mac-v80-probe")!=0)return 0;
    int error=(options & FSOPT_NOFOLLOW)?EACCES:0;
    IOLog("RAVYN-MACV80_GETATTR abi=80 attrs=%x options=%llx error=%d\n",attrs->commonattr,(unsigned long long)options,error);
    return error;
}



static volatile SInt32 task_gate;
static bool target_self(void){char name[32]={0};proc_name(proc_selfpid(),name,sizeof(name));return strcmp(name,"mac-v80-probe")==0;}
static int modern_quota(kauth_cred_t,struct mount *,int cmd,int id){
 if(!target_self())return 0;int error=id==424242?EACCES:0;
 IOLog("RAVYN-MACV80_QUOTA cmd=%x id=%d error=%d\n",cmd,id,error);return error;
}
static int modern_copyfile(kauth_cred_t,struct vnode *dvp,struct label *,struct vnode *tvp,struct label *tlabel,struct vnode *fvp,struct label *,struct componentname *,mode_t mode,int flags){
 if(!target_self())return 0;
 int error=(flags&CPF_OVERWRITE)?EACCES:0;
 if(!dvp||!fvp||(tvp==0&&tlabel!=0))error=EINVAL;
 IOLog("RAVYN-MACV80_COPYFILE target_present=%d mode=%o flags=%x error=%d\n",tvp!=0,(unsigned)mode,flags,error);return error;
}
static int modern_necp_open(kauth_cred_t,int flags){
 if(!target_self())return 0;int error=(flags&2)?EACCES:0;
 IOLog("RAVYN-MACV80_NECP_OPEN flags=%x error=%d\n",flags,error);return error;
}
static int modern_necp_action(kauth_cred_t,struct fileglob *fg,uint32_t action){
 if(!target_self())return 0;int error=action==1?EACCES:0;if(!fg)error=EINVAL;
 IOLog("RAVYN-MACV80_NECP_ACTION action=%u fg_valid=%d error=%d\n",action,fg!=0,error);return error;
}
static int modern_memstatus(kauth_cred_t,int32_t command,pid_t pid){
 if(!target_self())return 0;int error=command==0x7150?EACCES:0;
 IOLog("RAVYN-MACV80_MEMSTATUS command=%d pid=%d error=%d\n",command,pid,error);return error;
}
static int modern_iokit_service(kauth_cred_t,io_object_t service,unsigned int type){
 if(!target_self())return 0;
 bool is_lab=OSDynamicCast(RavynMacPolicyProbe,(OSObject *)service)!=0;
 int error=is_lab&&type==0x7150?EACCES:0;
 IOLog("RAVYN-MACV80_IOKIT_SERVICE lab=%d type=%x error=%d\n",is_lab,type,error);return error;
}
struct lab_proc_identity {uint64_t uniqueid;pid_t pid;int version;};
static_assert(sizeof(lab_proc_identity)==16,"exact pinned identity layout");
static bool identity_matches_self(struct proc_ident *ident){
 lab_proc_identity id;memcpy(&id,ident,sizeof(id));proc_t p=proc_self();
 bool ok=id.pid==proc_pid(p)&&id.uniqueid==proc_uniqueid(p)&&id.version==proc_pidversion(p);
 proc_rele(p);return ok;
}
static int modern_get_task(kauth_cred_t,struct proc_ident *ident,mac_policy_task_flavor_v80_t flavor){
 if(!target_self())return 0;
 bool valid=identity_matches_self(ident);int error=valid?0:EINVAL;
 if(valid&&flavor==1&&OSAddAtomic(0,&task_gate)==1)error=EACCES;
 IOLog("RAVYN-MACV80_GET_TASK flavor=%u identity_valid=%d error=%d\n",flavor,valid,error);return error;
}
static int modern_expose_task(kauth_cred_t,struct proc_ident *ident,mac_policy_task_flavor_v80_t flavor){
 if(!target_self())return 0;
 lab_proc_identity id;memcpy(&id,ident,sizeof(id));bool self=id.pid==proc_selfpid();
 int error=self&&OSAddAtomic(0,&task_gate)==2?EACCES:0;
 IOLog("RAVYN-MACV80_EXPOSE_TASK flavor=%u target=%d self=%d error=%d\n",flavor,id.pid,self,error);return error;
}

#define STACKSHOT_MAX_THREAD_NAME_SIZE 64
#define STACKSHOT_IO_NUM_PRIORITIES 4
struct probe_micro_snapshot {
	uint32_t                snapshot_magic;
	uint32_t                ms_cpu;  /* cpu number this snapshot was recorded on */
	uint64_t                ms_time; /* time at sample (seconds) */
	uint64_t                ms_time_microsecs;
	uint8_t                 ms_flags;
	uint16_t                ms_opaque_flags;        /* managed by external entity, e.g. fdrmicrod */
} __attribute__ ((packed));
struct probe_task_snapshot {
	uint32_t snapshot_magic;
	int32_t pid;
	uint64_t                uniqueid;
	uint64_t                user_time_in_terminated_threads;
	uint64_t                system_time_in_terminated_threads;
	uint8_t                 shared_cache_identifier[16];
	uint64_t                shared_cache_slide;
	uint32_t                nloadinfos;
	int                     suspend_count;
	int                     task_size;      /* pages */
	int                     faults;         /* number of page faults */
	int                     pageins;        /* number of actual pageins */
	int                     cow_faults;     /* number of copy-on-write faults */
	uint32_t                ss_flags;
	uint64_t                p_start_sec;    /* from the bsd proc struct */
	uint64_t                p_start_usec;   /* from the bsd proc struct */

	/*
	 * We restrict ourselves to a statically defined
	 * (current as of 2009) length for the
	 * p_comm string, due to scoping issues (osfmk/bsd and user/kernel
	 * binary compatibility).
	 */
	char                    p_comm[17];
	uint32_t                was_throttled;
	uint32_t                did_throttle;
	uint32_t                latency_qos;
	/*
	 * I/O Statistics
	 * XXX: These fields must be together.
	 */
	uint64_t                disk_reads_count;
	uint64_t                disk_reads_size;
	uint64_t                disk_writes_count;
	uint64_t                disk_writes_size;
	uint64_t                io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t                io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t                paging_count;
	uint64_t                paging_size;
	uint64_t                non_paging_count;
	uint64_t                non_paging_size;
	uint64_t                data_count;
	uint64_t                data_size;
	uint64_t                metadata_count;
	uint64_t                metadata_size;
	/* XXX: I/O Statistics end */

	uint32_t                donating_pid_count;
} __attribute__ ((packed));
struct probe_thread_snapshot {
	uint32_t                snapshot_magic;
	uint32_t                nkern_frames;
	uint32_t                nuser_frames;
	uint64_t                wait_event;
	uint64_t                continuation;
	uint64_t                thread_id;
	uint64_t                user_time;
	uint64_t                system_time;
	int32_t                 state;
	int32_t                 priority;    /*	static priority */
	int32_t                 sched_pri;   /* scheduled (current) priority */
	int32_t                 sched_flags; /* scheduler flags */
	char                    ss_flags;
	char                    ts_qos;      /* effective qos */
	char                    ts_rqos;     /* requested qos */
	char                    ts_rqos_override; /* requested qos override */
	char                    io_tier;
	char                    _reserved[3]; /* pad for 4 byte alignement packing */

	/*
	 * I/O Statistics
	 * XXX: These fields must be together
	 */
	uint64_t                disk_reads_count;
	uint64_t                disk_reads_size;
	uint64_t                disk_writes_count;
	uint64_t                disk_writes_size;
	uint64_t                io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t                io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
	uint64_t                paging_count;
	uint64_t                paging_size;
	uint64_t                non_paging_count;
	uint64_t                non_paging_size;
	uint64_t                data_count;
	uint64_t                data_size;
	uint64_t                metadata_count;
	uint64_t                metadata_size;
	/* XXX: I/O Statistics end */

	uint64_t                voucher_identifier; /* obfuscated voucher identifier */
	uint64_t                total_syscalls;
	char                    pth_name[STACKSHOT_MAX_THREAD_NAME_SIZE];
} __attribute__((packed));

static volatile SInt32 telemetry_callbacks,telemetry_valid,telemetry_errors,telemetry_frames;
static uint64_t telemetry_expected_unique;
static pid_t telemetry_expected_pid;
static void modern_telemetry(struct thread *,int error,const void *data,size_t length) {
 if(!target_self())return;
 OSIncrementAtomic(&telemetry_callbacks);
 bool valid=false;uint32_t frames=0;
 if(error==0&&data&&length>=sizeof(probe_micro_snapshot)+sizeof(probe_task_snapshot)){
  const unsigned char *bytes=(const unsigned char *)data;
  probe_micro_snapshot micro;probe_task_snapshot task;
  memcpy(&micro,bytes,sizeof(micro));memcpy(&task,bytes+sizeof(micro),sizeof(task));
  valid=micro.snapshot_magic==0x31c54011&&(micro.ms_flags&0x20)&&task.snapshot_magic==0xdecafbad&&task.pid==telemetry_expected_pid&&task.uniqueid==telemetry_expected_unique;
  /* Load-info word size is fixed by the sampled task's kUser64_p flag0x1. */
  size_t uuid_size=(task.ss_flags&1)?24:20;
  size_t offset=sizeof(micro)+sizeof(task)+(size_t)task.nloadinfos*uuid_size;
  if(offset<=length&&length-offset>=sizeof(probe_thread_snapshot)){
   probe_thread_snapshot thread;memcpy(&thread,bytes+offset,sizeof(thread));
   valid=valid&&thread.snapshot_magic==0xfeedface&&thread.nuser_frames>0;frames=thread.nuser_frames;
   size_t frame_size=(thread.ss_flags&1)?8:4;
   size_t start=offset+sizeof(thread)+((thread.ss_flags&4)?8:0);
   valid=valid&&thread.nkern_frames==0&&start<=length&&frames<=(length-start)/frame_size&&start+(size_t)frames*frame_size==length;
   if(valid)for(uint32_t i=0;i<frames;i++){uint64_t address=0;memcpy(&address,bytes+start+(size_t)i*frame_size,frame_size);if(address==0||address>=UINT64_C(0x800000000000))valid=false;}

  }else valid=false;
 }
 if(valid)OSIncrementAtomic(&telemetry_valid);else OSIncrementAtomic(&telemetry_errors);
 SInt32 prior=OSAddAtomic(0,&telemetry_frames);if((SInt32)frames>prior)OSAddAtomic((SInt32)frames-prior,&telemetry_frames);
 IOLog("RAVYN-MACV80_TELEMETRY error=%d length=%llu valid=%d frames=%u\n",error,(unsigned long long)length,valid,frames);
}


static_assert(sizeof(lab_syscall_filter_callbacks)==32,"pinned callback descriptor size");
static_assert(__builtin_offsetof(lab_syscall_filter_callbacks,mach_filter_cbfunc)==16,"pinned MACH callback offset");
static_assert(__builtin_offsetof(lab_syscall_filter_callbacks,kobj_filter_cbfunc)==24,"pinned KOBJ callback offset");
static unsigned char mach_filter_mask[16],kobj_filter_mask[512];
static volatile SInt32 filter_gate,filter_mach_evals,filter_kobj_evals;
static int filter_setup_checks,filter_setup_failures;
static size_t filter_mach_count,filter_kobj_count;
static void setup_check(bool ok){filter_setup_checks++;filter_setup_failures+=!ok;}
static int evaluate_mach(proc_t p,int number){
 if(!target(p))return KERN_SUCCESS;
 OSIncrementAtomic(&filter_mach_evals);int result=OSAddAtomic(0,&filter_gate)?KERN_NO_ACCESS:KERN_SUCCESS;
 IOLog("RAVYN-FILTER_MACH number=%d result=%d\n",number,result);return result;
}
static int evaluate_kobj(proc_t p,int message,int index){
 if(!target(p))return KERN_SUCCESS;
 OSIncrementAtomic(&filter_kobj_evals);int result=OSAddAtomic(0,&filter_gate)?KERN_NO_ACCESS:KERN_SUCCESS;
 IOLog("RAVYN-FILTER_KOBJ message=%d index=%d result=%d\n",message,index,result);return result;
}
static void filter_setup(void){
 filter_mach_count=proc_get_syscall_filter_mask_size(1);
 filter_kobj_count=proc_get_syscall_filter_mask_size(2);
 setup_check(filter_mach_count==128);setup_check(filter_kobj_count>0&&filter_kobj_count<=sizeof(kobj_filter_mask)*8);
 setup_check(proc_get_syscall_filter_mask_size(-1)==0);
 setup_check(proc_set_syscall_filter_callbacks(NULL)==EINVAL);
 lab_syscall_filter_callbacks badversion={99,NULL,evaluate_mach,evaluate_kobj};
 setup_check(proc_set_syscall_filter_callbacks(&badversion)==EINVAL);
 lab_syscall_filter_callbacks unsupported={1,evaluate_mach,NULL,NULL};
 setup_check(proc_set_syscall_filter_callbacks(&unsupported)==ENOTSUP);
 lab_syscall_filter_callbacks empty={1,NULL,NULL,NULL};
 setup_check(proc_set_syscall_filter_callbacks(&empty)==0);
 lab_syscall_filter_callbacks first={1,NULL,NULL,evaluate_kobj};
 setup_check(proc_set_syscall_filter_callbacks(&first)==0);
 lab_syscall_filter_callbacks partial={1,NULL,evaluate_mach,evaluate_kobj};
 setup_check(proc_set_syscall_filter_callbacks(&partial)==EPERM);
 lab_syscall_filter_callbacks second={1,NULL,evaluate_mach,NULL};
 setup_check(proc_set_syscall_filter_callbacks(&second)==0);
 setup_check(proc_set_syscall_filter_callbacks(&second)==EPERM);
 setup_check(proc_set_syscall_filter_index(0,200,7)==EINVAL);
 setup_check(proc_set_syscall_filter_index(2,200,-1)==EINVAL);
 setup_check(proc_set_syscall_filter_index(2,200,(int)filter_kobj_count)==EINVAL);
 setup_check(proc_set_syscall_filter_index(2,0x7fffffff,7)==ENOENT);
 setup_check(proc_set_syscall_filter_index(2,200,7)==0);
 memset(mach_filter_mask,0xff,sizeof(mach_filter_mask));
 mach_filter_mask[33>>3]&=~(1U<<(33&7));mach_filter_mask[29>>3]&=~(1U<<(29&7));
 memset(kobj_filter_mask,0xff,sizeof(kobj_filter_mask));kobj_filter_mask[7>>3]&=~(1U<<(7&7));
 IOLog("RAVYN-FILTER_SETUP checks=%d failures=%d mach_count=%llu kobj_count=%llu\n",filter_setup_checks,filter_setup_failures,(unsigned long long)filter_mach_count,(unsigned long long)filter_kobj_count);
}
static const int donor_filter_ids[365]={200,201,202,203,204,205,206,207,209,213,214,215,216,217,218,219,220,221,222,223,224,225,227,228,231,232,233,234,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,418,419,420,423,424,425,600,601,1000,1001,1002,1200,1201,2401,2402,2403,2405,2406,2407,2800,2801,2802,2803,2804,2805,2806,2807,2808,2809,2810,2811,2812,2813,2814,2816,2817,2818,2819,2820,2821,2822,2823,2824,2825,2826,2827,2828,2829,2830,2831,2832,2833,2834,2836,2837,2838,2839,2840,2841,2842,2843,2844,2845,2846,2847,2848,2849,2850,2851,2852,2853,2854,2855,2856,2857,2858,2859,2860,2861,2862,2863,2864,2865,2866,2867,2868,2869,2870,2871,2872,2873,2874,2875,2876,2877,2878,2879,2880,2881,2882,2883,2884,2885,2886,2887,2888,2889,3000,3001,3002,3003,3004,3005,3200,3201,3202,3203,3204,3205,3206,3207,3208,3209,3210,3211,3212,3213,3214,3215,3216,3217,3218,3219,3220,3221,3222,3223,3224,3225,3226,3227,3228,3229,3230,3231,3232,3233,3234,3235,3236,3237,3238,3239,3240,3241,3242,3400,3401,3402,3403,3404,3405,3406,3407,3408,3409,3410,3411,3412,3413,3414,3415,3418,3419,3420,3421,3423,3424,3425,3426,3427,3428,3429,3430,3431,3432,3433,3434,3435,3436,3437,3438,3439,3440,3441,3442,3443,3444,3445,3446,3447,3448,3449,3450,3451,3452,3453,3455,3456,3457,3458,3459,3460,3461,3462,3463,3600,3601,3602,3603,3604,3605,3606,3607,3608,3609,3610,3611,3612,3613,3614,3615,3616,3617,3618,3621,3622,3623,3624,3625,3626,3627,3628,3630,3800,3801,3802,3803,3804,3805,3806,3807,3808,3809,3810,3811,3812,3813,3814,3815,3816,3817,3818,3819,3821,3822,3823,3824,3825,3826,3830,3831,3832,4000,4001,4002,4003,4004,4005,4006,4007,4008,4009,4010,4800,4801,4802,4803,4804,4805,4806,4807,4808,4809,4810,4811,4812,4813,4814,4815,4816,4817,4818,4819,4820,4821,4900,4901,4902,5400,5401,5402,5403,5404,5600,5601,6200,6201,8000,8001};
static int filter_command(proc_t p,int callnum,user_addr_t arg){
 if(callnum==730||callnum==739){
  SInt32 results[8]={filter_setup_checks,filter_setup_failures,(SInt32)filter_mach_count,(SInt32)filter_kobj_count,OSAddAtomic(0,&filter_mach_evals),OSAddAtomic(0,&filter_kobj_evals),OSAddAtomic(0,&filter_gate),0};
  return copyout(results,arg,sizeof(results));
 }
 if(callnum==731)return proc_set_syscall_filter_mask(p,1,mach_filter_mask,filter_mach_count);
 if(callnum==732)return proc_set_syscall_filter_mask(p,1,NULL,0);
 if(callnum==733)return proc_set_syscall_filter_mask(p,2,kobj_filter_mask,filter_kobj_count);
 if(callnum==734)return proc_set_syscall_filter_mask(p,2,NULL,0);
 if(callnum==735){OSAddAtomic(1-OSAddAtomic(0,&filter_gate),&filter_gate);return 0;}
 if(callnum==736){OSAddAtomic(-OSAddAtomic(0,&filter_gate),&filter_gate);return 0;}
 if(callnum==737){kobj_filter_mask[0]|=0x80;return 0;}
 if(callnum==738){kobj_filter_mask[0]&=0x7f;return 0;}
 if(callnum==740){
  setup_check(proc_set_syscall_filter_mask(p,1,mach_filter_mask,filter_mach_count-1)==EINVAL);
  setup_check(proc_set_syscall_filter_mask(p,2,kobj_filter_mask,filter_kobj_count+1)==EINVAL);
  setup_check(proc_set_syscall_filter_mask(p,99,mach_filter_mask,filter_mach_count)==EINVAL);
  setup_check(proc_set_syscall_filter_mask(NULL,1,mach_filter_mask,filter_mach_count)==EINVAL);
  return filter_setup_failures?EINVAL:0;
 }
 if(callnum==741){mach_filter_mask[29>>3]|=1U<<(29&7);return 0;}
 if(callnum==742){
  int mapped=0,missing=0,unexpected=0;
  for(int index=0;index<365;index++){
   int error=proc_set_syscall_filter_index(2,donor_filter_ids[index],index);
   mapped+=error==0;missing+=error==ENOENT;unexpected+=error!=0&&error!=ENOENT;
   IOLog("RAVYN-FILTER_DONOR index=%d message=%d rc=%d\n",index,donor_filter_ids[index],error);
  }
  int result[4]={365,mapped,missing,unexpected};
  IOLog("RAVYN-FILTER_DONOR_RESULT entries=%d mapped=%d missing=%d unexpected=%d\n",365,mapped,missing,unexpected);
  return copyout(result,arg,sizeof(result));
 }

 return ENOTSUP;
}


struct lab_fixed_descriptor {
 void *zone,*stats;const char *name;void *next;const char *signature;
 uint32_t flags,size;void *unused1,*unused2;
};
struct lab_variable_descriptor {
 uint16_t version,header_size;uint32_t type_size;void *stats;const char *name;void *next;
 uint16_t heap_start;uint8_t zones[20];const char *header_signature,*type_signature;uint32_t flags;
};
static_assert(sizeof(lab_fixed_descriptor)==64,"fixed ABI");
static_assert(sizeof(lab_variable_descriptor)==80,"variable ABI");
extern "C" void *lab_alloc_fixed(lab_fixed_descriptor *) __asm("_IOMallocTypeImpl");
extern "C" void lab_free_fixed(lab_fixed_descriptor *,void *) __asm("_IOFreeTypeImpl");
extern "C" void *lab_alloc_variable(lab_variable_descriptor *,vm_size_t) __asm("_IOMallocTypeVarImpl");
extern "C" void lab_free_variable(lab_variable_descriptor *,void *,vm_size_t) __asm("_IOFreeTypeVarImpl");
extern "C" void *lab_alloc_data(vm_size_t) __asm("_IOMallocData");
extern "C" void lab_free_data(void *,vm_size_t) __asm("_IOFreeData");
extern "C" boolean_t ravyn_kalloc_is_data(void *);
static lab_fixed_descriptor fixed_descriptors[]={
{0,0,"site.typeof(*pd)",0,"211",0x64,24,0,0},
{0,0,"site.struct protected_device",0,"211",0x64,24,0,0},
{0,0,"site.struct iofilter",0,"",0x6c,24,0,0},
{0,0,"site.typeof(*filter)",0,"",0x6c,24,0,0},
{0,0,"site.struct pathindex",0,"12221",0x64,40,0,0},
{0,0,"site.typeof(*index)",0,"12221",0x64,40,0,0},
{0,0,"site.typeof(*node)",0,"322111",0x64,48,0,0},
{0,0,"site.struct pathindex_node",0,"322111",0x64,48,0,0},
{0,0,"site.typeof(*new_node)",0,"322111",0x64,48,0,0},
{0,0,"site.struct macl",0,"2212112332133",0x64,104,0,0},
{0,0,"site.struct macl_entry",0,"112222",0x64,48,0,0},
{0,0,"site.typeof(*entry)",0,"112222",0x64,48,0,0},
{0,0,"site.typeof(*macl)",0,"2212112332133",0x64,104,0,0},
{0,0,"site.struct sb_reference",0,"111221",0x64,48,0,0},
{0,0,"site.struct sb_holder",0,"111111111111112",0x64,120,0,0},
{0,0,"site.typeof(*ref)",0,"111221",0x64,48,0,0},
{0,0,"site.typeof(*holder)",0,"111111111111112",0x64,120,0,0},
{0,0,"site.typeof(*fc->socket.sockname)",0,"",0x6c,128,0,0},
{0,0,"site.struct sockaddr_storage",0,"",0x6c,128,0,0},
{0,0,"site.typeof(*state)",0,"12111",0x64,40,0,0},
{0,0,"site.struct profile_state",0,"12111",0x64,40,0,0},
{0,0,"site.typeof(*state)",0,"12111",0x64,40,0,0},
{0,0,"site.typeof(*entry)",0,"211111",0x64,48,0,0},
{0,0,"site.typeof(*event)",0,"121122",0x64,48,0,0},
{0,0,"site.typeof(*entry)",0,"211111",0x64,48,0,0},
{0,0,"site.typeof(*copied_pe)",0,"121122",0x64,48,0,0},
{0,0,"site.typeof(*entry)",0,"211111",0x64,48,0,0},
{0,0,"site.struct filecache_entry",0,"11111121",0x64,64,0,0},
{0,0,"site.typeof(*entry)",0,"11111121",0x64,64,0,0},
{0,0,"site.struct tm_device_uuid",0,"122222",0x64,48,0,0},
{0,0,"site.struct sb_mount_info",0,"2212",0x64,32,0,0},
{0,0,"site.typeof(*minfo)",0,"2212",0x64,32,0,0},
{0,0,"site.struct sandbox_state",0,"12211222",0x64,64,0,0},
{0,0,"site.typeof(*state)",0,"12211222",0x64,64,0,0},
{0,0,"site.typeof(*state)",0,"12211222",0x64,64,0,0},
{0,0,"site.typeof(*extensions)",0,"1111111111111111112222",0x64,176,0,0},
{0,0,"site.typeof(*esc)",0,"112",0x64,24,0,0},
{0,0,"site.typeof(*ec)",0,"111",0xe4,24,0,0},
{0,0,"site.typeof(*extensions)",0,"1111111111111111112222",0x64,176,0,0},
{0,0,"site.typeof(*ex)",0,"12222222132211",0x64,112,0,0},
{0,0,"site.typeof(*esc)",0,"112",0x64,24,0,0},
{0,0,"site.typeof(*ex)",0,"12222222132211",0x64,112,0,0},
{0,0,"site.typeof(*ec)",0,"111",0xe4,24,0,0},
{0,0,"site.typeof(*ec)",0,"111",0xe4,24,0,0},
{0,0,"site.struct policy_id_allocation",0,"112",0x64,24,0,0},
{0,0,"site.typeof(*entry)",0,"112",0x64,24,0,0},
{0,0,"site.typeof(*entry)",0,"112",0x64,24,0,0},
{0,0,"site.typeof(*entry)",0,"112",0x64,24,0,0},
{0,0,"site.struct macl_xlate_entry",0,"1111112222221",0x64,104,0,0},
{0,0,"site.struct macl_xlate_entry",0,"1111112222221",0x64,104,0,0},
{0,0,"site.struct sb_packbuff",0,"2222211",0x64,56,0,0},
{0,0,"site.typeof(*new)",0,"2222211",0x64,56,0,0},
{0,0,"site.struct sb_packbuff",0,"2222211",0x64,56,0,0},
{0,0,"site.typeof(*pb)",0,"2222211",0x64,56,0,0},
{0,0,"site.proc_stash",0,"11",0xe4,16,0,0},
{0,0,"site.typeof(*stash)",0,"11",0xe4,16,0,0},
{0,0,"site.typeof(*stash)",0,"11",0xe4,16,0,0},
{0,0,"site.typeof(*sblabel)",0,"222322222222222222221",0x64,168,0,0},
{0,0,"site.typeof(*sblabel)",0,"222322222222222222221",0x64,168,0,0},
{0,0,"site.typeof(*sblabel)",0,"222322222222222222221",0x64,168,0,0},
{0,0,"site.typeof(*sblabel)",0,"222322222222222222221",0x64,168,0,0},
{0,0,"site.struct pending_update",0,"121212",0x64,48,0,0},
{0,0,"site.typeof(*pending)",0,"121212",0x64,48,0,0},
{0,0,"site.struct pending_approval_entry",0,"1122112222",0x64,80,0,0},
{0,0,"site.typeof(*entry)",0,"1122112222",0x64,80,0,0},
{0,0,"site.typeof(*entry)",0,"1122112222",0x64,80,0,0},
};
static lab_variable_descriptor variable_descriptors[]={
{1,0,16,0,"site.typeof(*free_entries)",0,0,{0},NULL,"21",0x64},
{1,0,16,0,"site.struct bsddev_cache_entry",0,0,{0},NULL,"21",0x64},
{1,0,16,0,"site.typeof(*entries)",0,0,{0},NULL,"21",0x64},
{1,0,8,0,"site.typeof(*nodelist->nodes)",0,0,{0},NULL,"1",0xe4},
{1,0,8,0,"site.typeof(*new_nodes)",0,0,{0},NULL,"1",0xe4},
{1,0,8,0,"site.typeof(*nodelist->nodes)",0,0,{0},NULL,"1",0xe4},
{1,0,24,0,"site.struct userret_task_entry",0,0,{0},NULL,"221",0x64},
{1,0,24,0,"site.typeof(*new_tasks)",0,0,{0},NULL,"221",0x64},
{1,0,24,0,"site.typeof(*userret_tasks)",0,0,{0},NULL,"221",0x64},
{1,0,8,0,"site.struct variable_info",0,0,{0},NULL,"",0x6c},
{1,0,8,0,"site.matchExpr_t",0,0,{0},NULL,"1",0xe4},
{1,0,8,0,"site.typeof(*pr->regexes)",0,0,{0},NULL,"1",0xe4},
{1,0,8,0,"site.typeof(*pr->variables)",0,0,{0},NULL,"",0x6c},
{1,0,8,0,"site.typeof(*ancestors)",0,0,{0},NULL,"1",0xe4},
{1,0,8,0,"site.typeof(*ancestors)",0,0,{0},NULL,"1",0xe4},
{1,0,16,0,"site.struct storage_class_descriptor",0,0,{0},NULL,"12",0x64},
{1,0,16,0,"site.typeof(*storage_class_descriptors)",0,0,{0},NULL,"12",0x64},

};
static bool allocator_zero(void *p,vm_size_t n) {
 if(!p)return false;
 for(vm_size_t i=0;i<n;i++)if(((unsigned char *)p)[i])return false;
 return true;
}
static void allocator_check(bool ok,int &checks,int &failures,const char *name,int index){
 checks++;failures+=!ok;if(!ok)IOLog("RAVYN-ALLOCATOR_FAIL name=%s index=%d\n",name,index);
}
static int allocator_probe(user_addr_t output){
 int checks=0,failures=0;
 for(unsigned i=0;i<sizeof(fixed_descriptors)/sizeof(fixed_descriptors[0]);i++){
  lab_fixed_descriptor *d=&fixed_descriptors[i];void *p=lab_alloc_fixed(d);
  allocator_check(p&&allocator_zero(p,d->size),checks,failures,"fixed_zero",i);
  allocator_check(p&&!ravyn_kalloc_is_data(p),checks,failures,"fixed_default_fallback",i);
  if(p){memset(p,0xa5,d->size);lab_fixed_descriptor other=*d;other.name="distinct free descriptor";lab_free_fixed(&other,p);}
 }
 for(unsigned i=0;i<sizeof(variable_descriptors)/sizeof(variable_descriptors[0]);i++){
  lab_variable_descriptor *d=&variable_descriptors[i];
  const vm_size_t sizes[]={0,1,15,16,17,79,128,513,8192,8193,65553};
  for(unsigned n=0;n<sizeof(sizes)/sizeof(sizes[0]);n++){
   vm_size_t size=sizes[n];void *p=lab_alloc_variable(d,size);
   allocator_check(p&&allocator_zero(p,size),checks,failures,"variable_zero",i);
   allocator_check(p&&(!!ravyn_kalloc_is_data(p)==!!(d->flags&8)),checks,failures,"variable_heap",i);
   if(p){memset(p,0x5a,size);lab_variable_descriptor other=*d;other.name="distinct variable free";lab_free_variable(&other,p,size);}
  }
  allocator_check(lab_alloc_variable(d,1ULL<<63)==NULL,checks,failures,"variable_overflow",i);
  lab_free_variable(d,NULL,1ULL<<63);
 }
 const vm_size_t sizes[]={0,1,15,16,17,47,48,49,79,80,81,127,128,129,511,512,513,1024,2048,4096,8192,8193,65553,1048576};
 for(unsigned n=0;n<sizeof(sizes)/sizeof(sizes[0]);n++){
  vm_size_t size=sizes[n];void *p=lab_alloc_data(size);
  allocator_check(p&&ravyn_kalloc_is_data(p),checks,failures,"data_storage",n);
  if(p){memset(p,0xc3,size);allocator_check(size==0||((unsigned char *)p)[size-1]==0xc3,checks,failures,"data_real_bytes",n);lab_free_data(p,size);}
 }
 allocator_check(lab_alloc_data(1ULL<<63)==NULL,checks,failures,"data_overflow",0);
 lab_free_data(NULL,1ULL<<63);lab_free_fixed(NULL,NULL);lab_free_variable(NULL,NULL,1ULL<<63);
 for(unsigned round=0;round<40;round++){
  lab_variable_descriptor *d=&variable_descriptors[0];void *p=lab_alloc_variable(d,113);
  allocator_check(p&&allocator_zero(p,113),checks,failures,"reused_zero",round);
  if(p){memset(p,0xa5,113);lab_free_variable(d,p,113);}
 }
 int result[4]={checks,failures,(int)(sizeof(fixed_descriptors)/sizeof(fixed_descriptors[0])),(int)(sizeof(variable_descriptors)/sizeof(variable_descriptors[0]))};
 IOLog("RAVYN-ALLOCATOR_RESULT checks=%d failures=%d fixed=%d variable=%d\n",result[0],result[1],result[2],result[3]);
 return copyout(result,output,sizeof(result));
}

static volatile SInt32 syscall_effects;
static int modern_mac_syscall(struct proc *p,const char *policy,int callnum) {
    if(!target(p))return 0;
    int error=(callnum==701||callnum==703)?EACCES:0;
    IOLog("RAVYN-MACV80_SYSCALL_CHECK target=%s call=%d error=%d\n",policy,callnum,error);
    return error;
}
static int legacy_policy_syscall(struct proc *p,int callnum,user_addr_t arg) {
    if(!target(p))return EPERM;
    if(callnum==750)return allocator_probe(arg);
    if(callnum>=730&&callnum<=742)return filter_command(p,callnum,arg);
    if(callnum==720){telemetry_expected_unique=proc_uniqueid(p);telemetry_expected_pid=proc_pid(p);return mac_schedule_telemetry();}
    if(callnum==721){SInt32 results[4]={OSAddAtomic(0,&telemetry_callbacks),OSAddAtomic(0,&telemetry_valid),OSAddAtomic(0,&telemetry_errors),OSAddAtomic(0,&telemetry_frames)};return copyout(results,arg,sizeof(results));}

    if(callnum>=710&&callnum<=712){OSAddAtomic(-OSAddAtomic(0,&task_gate),&task_gate);OSAddAtomic(callnum==710?1:callnum==712?2:0,&task_gate);return 0;}
    if(callnum==701||callnum==702)OSIncrementAtomic(&syscall_effects);
    else if(callnum!=700)return ENOTSUP;
    SInt32 effects=OSAddAtomic(0,&syscall_effects);
    IOLog("RAVYN-MACV80_SYSCALL_HANDLER call=%d effects=%d\n",callnum,(int)effects);
    return copyout(&effects,arg,sizeof(effects));
}

bool RavynMacPolicyProbe::start(IOService *provider) {
    if(!IOService::start(provider))return false;
    old_ops.mpo_proc_check_signal=legacy_signal;
    old_ops.mpo_policy_syscall=legacy_policy_syscall;
    old_ops.mpo_vnode_check_getattrlist=legacy_getattr;
    old_ops.mpo_policy_init=policy_init;old_ops.mpo_policy_destroy=policy_destroy;
    old_conf.mpc_name="ravyn_v80_lab_legacy";old_conf.mpc_fullname="ravyn lab legacy policy";
    old_conf.mpc_ops=&old_ops;old_conf.mpc_loadtime_flags=MPC_LOADTIME_FLAG_UNLOADOK;
    new_ops.mpo_proc_check_signal=modern_signal;
    new_ops.mpo_thread_telemetry=modern_telemetry;
    new_ops.mpo_mount_check_quotactl=modern_quota;
    new_ops.mpo_vnode_check_copyfile=modern_copyfile;
    new_ops.mpo_necp_check_open=modern_necp_open;
    new_ops.mpo_necp_check_client_action=modern_necp_action;
    new_ops.mpo_proc_check_memorystatus_control=modern_memstatus;
    new_ops.mpo_iokit_check_open_service=modern_iokit_service;
    new_ops.mpo_proc_check_get_task_with_flavor=modern_get_task;
    new_ops.mpo_proc_check_expose_task_with_flavor=modern_expose_task;
    new_ops.mpo_proc_check_syscall_mac=modern_mac_syscall;
    new_ops.mpo_vnode_check_getattrlist=modern_getattr;
    new_ops.mpo_policy_init=policy_init;new_ops.mpo_policy_destroy=policy_destroy;
    new_conf.mpc_name="ravyn_v80_lab_modern";new_conf.mpc_fullname="ravyn lab version80 policy";
    new_conf.mpc_ops=(const struct mac_policy_ops *)&new_ops;
    new_conf.mpc_loadtime_flags=MPC_LOADTIME_FLAG_UNLOADOK;
    new_ops.unsupported_slot_31=1;
    int rejected=mac_policy_register_v80(&new_conf,&modern_handle,0);
    bool unchanged=new_conf.mpc_list==0&&new_conf.mpc_runtime_flags==0&&probe_initialized==0;
    new_ops.unsupported_slot_31=0;
    int oldrc=mac_policy_register(&old_conf,&legacy_handle,0);legacy_loaded=oldrc==0;
    int newrc=mac_policy_register_v80(&new_conf,&modern_handle,0);modern_loaded=newrc==0;
    bool retained=new_conf.mpc_ops==(const struct mac_policy_ops *)&new_ops;
    IOLog("RAVYN-MACV80_REGISTER reject=%d expected=%d unchanged=%d legacy=%d modern=%d initialized=%d original_ops_retained=%d\n",rejected,ENOTSUP,unchanged,oldrc,newrc,probe_initialized,retained);
    if(!legacy_loaded||!modern_loaded||rejected!=ENOTSUP||!unchanged||probe_initialized!=2||!retained) {
        if(modern_loaded){mac_policy_unregister(modern_handle);modern_loaded=false;}
        if(legacy_loaded){mac_policy_unregister(legacy_handle);legacy_loaded=false;}
        IOLog("RAVYN-MACV80_SETUP_FAILED\n");return false;
    }
    filter_setup();
    registerService();return true;
}
void RavynMacPolicyProbe::stop(IOService *provider) {
    int modern=modern_loaded?mac_policy_unregister(modern_handle):0;modern_loaded=false;
    int legacy=legacy_loaded?mac_policy_unregister(legacy_handle):0;legacy_loaded=false;
    IOLog("RAVYN-MACV80_UNREGISTER modern=%d legacy=%d destroyed=%d shadow_cleared=%d\n",modern,legacy,probe_destroyed,new_conf.mpc_list==0);
    IOService::stop(provider);
}
