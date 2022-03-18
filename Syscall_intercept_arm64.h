void print_register_enter(struct user_pt_regs regs,pid_t pid,char* _NR,uint64_t num);
void print_register_leave(struct user_pt_regs regs,pid_t pid,char* _NR,uint64_t num);
void enterSysCall(pid_t pid);
void leaveSysCall(pid_t pid);
void getdata(pid_t pid, uint64_t addr, char * str, long sz);
void putdata(pid_t pid, uint64_t addr, char * str, long sz);
void get_addr_path(pid_t pid,uint64_t addr,char * path_result);
void print_threads();
void getNameByPid(pid_t pid, char *task_name);
void get_tids(const pid_t pid);
void print_status(char* tag,pid_t wait_pid,int status);

// #define DEBUG

#if defined(__aarch64__)
	#define ARM_x0 regs[0]
    #define ARM_x1 regs[1]
    #define ARM_x2 regs[2]
	#define ARM_x8 regs[8]
	#define ARM_lr regs[30]
	#define ARM_sp sp
	#define ARM_pc pc
	#define ARM_cpsr pstate
	#define NT_PRSTATUS 1
	#define NT_foo 1
#endif

