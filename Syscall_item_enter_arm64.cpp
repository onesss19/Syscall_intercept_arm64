#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>


#include "Syscall_arm64.h"
#include "Syscall_item_enter_arm64.h"
#include "Syscall_intercept_arm64.h"


void openat_item(pid_t pid,user_pt_regs regs){
    char        filename[256];
    char        path[256];
    uint32_t    filenamelength=0;

    get_addr_path(pid,regs.ARM_x1,path);
    if(strstr(path,"/data/app")!=0 || strstr(path,"[anon:libc_malloc]")!=0){
        getdata(pid,regs.ARM_x1,filename,256);
        if(strcmp(filename,"/dev/ashmem")!=0){
            print_register_enter(regs,pid,(char*)"__NR_openat",regs.ARM_x8);
            printf("filename: %s\n",filename);
            printf("path: %s\n",path);
            if(strcmp(filename,"/proc/sys/kernel/random/boot_id")==0){
                char tmp[256]="/data/local/tmp/boot_id";
                filenamelength=strlen(tmp)+1;
                putdata(pid,regs.ARM_x1,tmp,filenamelength);
                getdata(pid,regs.ARM_x1,filename,256);
                printf("changed filename: %s\n",filename);
            }
        }
    }
}

void read_item(pid_t pid,user_pt_regs regs){
    print_register_enter(regs,pid,(char*)"__NR_read",regs.ARM_x8);
}

void SysCall_item_enter_switch(pid_t pid,user_pt_regs regs){
    switch (regs.ARM_x8)
    {
    case __NR_openat:
        openat_item(pid,regs);
        break;
    default:
        break;
    }
}