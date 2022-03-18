#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <cstdio>
#include <linux/ptrace.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <map>

#include "Syscall_arm64.h"
#include "Syscall_item_enter_arm64.h"
#include "Syscall_intercept_arm64.h"

#define BUF_SIZE 1024
#define ENTER 1
#define LEAVE 0


void show_helper(){
    printf(
            "\nSyscall_intercept -z <zygote_pid> -n <appname> -p <target_pid>\n"
            "options:\n"
            "\t-z <zygote_pid> : pid of zygote\n"
            "\t-t <appname> : application name\n"
            "\t-p <target_pid>: pid of application\n"
    );
}


int         status;
int         success = 0;
pid_t       wait_pid; 
pid_t       target_pid = -1;
pid_t       zygote_pid = -1;
char        appname[128];
int         tids_count=0;
std::vector<pid_t>      target_tids;
std::map<pid_t,int>     enter_or_leave;

int main(int argc,char* argv[]){
    int         opt;
    char*       optString = (char*)"p:n:hz:";
    if (argc < 3){
        show_helper();
        return 0;
    }
    while((opt = getopt(argc,argv,optString))!= -1){
        if(opt == 'p'){
            target_pid = atoi(optarg);
        }else if(opt == 'z'){
            zygote_pid = atoi(optarg);
        }else if(opt == 'n'){
            strcpy(appname,optarg);
        }else if(opt == 'h'){
            show_helper();
            return 0;
        }
    }
    if(zygote_pid == -1 && target_pid == -1){
        show_helper();
        return 0;
    }

    if(zygote_pid!=-1){
        printf("zygote_pid: %d\n",zygote_pid);
        printf("appname: %s\n",appname);

        // 附加到zygote进程
        int res = ptrace(PTRACE_ATTACH,zygote_pid,0,0);
        if(res == -1){
            printf("res: %d\n",res);
            printf("hook zygote error\n");
            show_helper();
            return -1;
        }
        // 等待附加完成
        waitpid(zygote_pid, NULL, 0);

        // 拦截 zygote 进程的 fork
        res = ptrace(PTRACE_SETOPTIONS, zygote_pid, (void *)0, (void *)(PTRACE_O_TRACEFORK));
        printf("ptrace zygote PTRACE_O_TRACEFORK res: %d\n",res);
        if (res == -1) {
            printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
            return -1;
        }
        // 让zygote恢复运行
        ptrace(PTRACE_CONT, zygote_pid, (void *)0, 0);
        printf("zygote continue \n");
        
        for (;;) {
            // fork后子进程的pid
            wait_pid = waitpid(-1, &status, __WALL | WUNTRACED);
            if(status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))){
                printf("fork出子进程 status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) %d\n",wait_pid);
            }
            if (wait_pid==zygote_pid){ //如果发出信号进程的进程号跟pid一致，则说明它是被跟踪程序的父进程，否则是被跟踪程序的子进程
                if(WIFSTOPPED(status)){
                    printf("zygote continue \n");
                    ptrace(PTRACE_CONT,wait_pid,0,0);
                    continue;
                }
            }
            // 判断fork后的程序是不是我们指定的应用
            if (wait_pid != 0 && wait_pid!=zygote_pid){
                char name[256]={0};
                getNameByPid(wait_pid,name);
            #ifdef DEBUG
                printf("wait_pid: %d,name: %s\n",wait_pid,name);
            #endif
                if (strstr(appname, name) != 0) {
                    printf("匹配到appname: %s\n",appname);
                    // detach from zygote
                    ptrace(PTRACE_DETACH, zygote_pid, 0, (void *)SIGCONT);
                    printf("Detach from zygote\n");
                    // now perform on new process
                    target_pid = wait_pid;
                    printf("appname: %s pid: %d\n",appname,target_pid);
                    success = 1;
                    // 拦截目标进程的clone和exit,clone重要 exit调试用
                    res = ptrace(PTRACE_SETOPTIONS, target_pid, (void *)0, (void *)(PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT|PTRACE_O_TRACEVFORK));
                    printf("ptrace PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT res: %d\n",res);
                    if (res == -1) {
                        printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
                        return -1;
                    }
                    target_tids.push_back(target_pid);
                    enter_or_leave[target_pid]=ENTER;tids_count++;
                    break;
                } else {
                    // 不是的话就continue
                    ptrace(PTRACE_SYSCALL, wait_pid, 0, 0);
                    continue;
                }
            }
        }
    }else if(target_pid != -1){
        //  获取所有线程
        get_tids(target_pid);
    #ifdef DEBUG
        print_threads();
    #endif
        // 附加到目标进程的所有线程
        for(int i=0;i<target_tids.size();i++){
            int res = ptrace(PTRACE_ATTACH,target_tids[i],0,0);
            if(res == -1){
                printf("ptrace thread error\n");
                show_helper();
                return -1;
            }else{
                printf("ptrace 到线程%d\n",target_tids[i]);
            }
        }
        printf("附加模式启动完毕，进入success\n");
        // 等待附加完成，会收到一个SIGSTOP（19
        wait_pid = waitpid(target_pid, &status, __WALL | WUNTRACED);
        print_status((char*)"init",wait_pid,status);

        // 拦截目标进程的clone和exit,clone重要 exit调试用
        int res = ptrace(PTRACE_SETOPTIONS, wait_pid, (void *)0, (void *)(PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT|PTRACE_O_TRACEVFORK));
        printf("ptrace PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT res: %d\n",res);
        if (res == -1) {
            printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
            return -1;
        }
        
        success=1;
    }
    
    pid_t tmp_pid;
    // 获取到目标进程pid
    if (success) { // 没有break
        // 获取到目标进程pid后，拦截它的system_call
        ptrace(PTRACE_SYSCALL, target_pid, 0, 0);
        while (1) {
            wait_pid = waitpid(-1, &status, __WALL | WUNTRACED);
            if(enter_or_leave.find(wait_pid)==enter_or_leave.end()){
                enter_or_leave[wait_pid]=ENTER; // 设置新线程 （确保
            }

            if(WIFEXITED(status)){ // 自己退出的时候
            #ifdef DEBUG
                print_status((char*)"exit",wait_pid,status);
                printf("pid: %d,exited\n",wait_pid);
            #endif
                for (int i=0; i<target_tids.size(); ++i){
                    if(target_tids[i]==wait_pid){
                        target_tids.erase(target_tids.begin()+i);
                        break;
                    }
                }
                tids_count--;
            #ifdef DEBUG
                print_threads();
            #endif
                continue;
            }

            if(WIFSTOPPED(status)){
                if(WSTOPSIG(status) == SIGSTOP){
                    if(zygote_pid == -1){ // attach 模式多线程处理
                        // 拦截目标进程的clone和exit,clone重要 exit调试用
                        int res = ptrace(PTRACE_SETOPTIONS, wait_pid, (void *)0, (void *)(PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT|PTRACE_O_TRACEVFORK));
                        printf("ptrace PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXIT res: %d\n",res);
                        if (res == -1) {
                            printf("FATAL ERROR: ptrace(PTRACE_SETOPTIONS, ...)\n");
                            return -1;
                        }  
                    }
                }
                if(status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))){
                    ptrace(PTRACE_GETEVENTMSG, wait_pid, 0, &tmp_pid);      // The PID of the new thread can be retrieved with PTRACE_GETEVENTMSG 
                    target_tids.push_back(tmp_pid);
                    tids_count++;
                }
                if(status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))){
                    ptrace(PTRACE_GETEVENTMSG, wait_pid, 0, &tmp_pid);      // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG 
                    target_tids.push_back(tmp_pid);
                    tids_count++;
                }
                if(status>>8 == SIGTRAP && enter_or_leave[wait_pid]==ENTER){
                    enterSysCall(wait_pid);
                }else if(status>>8 == SIGTRAP && enter_or_leave[wait_pid]==LEAVE){
                    leaveSysCall(wait_pid);
                }
                ptrace(PTRACE_SYSCALL, wait_pid, 0, 0);
            }
            if (WIFSIGNALED(status)){ // 仅仅在线程强制结束时会收到（SIGKILL 9），不会走上面的WIFEXITED
            #ifdef DEBUG
                print_status((char*)"signal",wait_pid,status);
            #endif
			}
        }
    }
    return 0;
}

void print_register_enter(struct user_pt_regs regs,pid_t pid,char* _NR,uint64_t num){
    printf("\nEnter Syscall>>>\ttid: %d call syscall: %s %lu\n",pid,_NR,num);
    printf("regs.ARM_x0: 0x%llx\n",regs.ARM_x0);
    printf("regs.ARM_x1: 0x%llx\n",regs.ARM_x1);
    printf("regs.ARM_x2: 0x%llx\n",regs.ARM_x2);
    printf("regs.ARM_lr: 0x%llx\n",regs.ARM_lr);
}

void print_register_leave(struct user_pt_regs regs,pid_t pid,char* _NR,uint64_t num){
    printf("\nLeave Syscall>>>\ttid: %d call syscall: %s %lu\n",pid,_NR,num);
    printf("regs.ARM_x0: %llu\n",regs.ARM_x0);
}

void enterSysCall(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);
    SysCall_item_enter_switch(pid,regs);
    enter_or_leave[pid]=LEAVE;
}
void leaveSysCall(pid_t pid) {
    struct user_pt_regs regs;
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);
    // SysCall_item_leave_switch
    enter_or_leave[pid]=ENTER;
}


const int long_size = sizeof(long);
void getdata(pid_t pid, uint64_t addr, char * str, long sz)
{
    int i = 0, j = sz / long_size;
    char *s = str;
    while (i < j) {
        *(long *)(s + i * 8) = ptrace(PTRACE_PEEKDATA, pid, addr + i * 8, NULL);
        ++ i;
    }
    j = sz % long_size;
    if (j != 0) {
        *(long *)(s + i * 8) = ptrace(PTRACE_PEEKDATA, pid, addr + i * 8, NULL);
    }
}

void putdata(pid_t pid, uint64_t addr, char * str, long sz)
{
    int i = 0, j = sz / long_size;
    char *s = str;
    while (i < j) {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
        ++ i;
    }
    j = sz % long_size;
    if (j != 0) {
        ptrace(PTRACE_POKEDATA, pid, addr + i * 8, *(long *)(s + i * 8));
    }
}

void get_addr_path(pid_t pid,uint64_t addr,char * path_result){
    char            filename[256];
    char            tmp[512];
    uint64_t        base;
    uint64_t        end;
    uint64_t        offset;
    char            perm[5];
    char            path[256];

    sprintf(filename,"/proc/%d/maps",pid);
    FILE* fd= fopen(filename,"r");
    if (fd) {
        while (fgets(tmp, 512, fd)) {
            if (sscanf(tmp, "%lx-%lx %4s %lx %*s %*s %s", &base, &end, perm, &offset, path) !=5) {
                continue;
            }
            // printf("base %lld,end %lld,addr %lld,%d&%d\n",base,end,addr,addr>base,addr<end);
            if(addr>base&&addr<end){
                strcpy(path_result,path);
                // printf("path: %s\n",path_result);
                return;
            }
        }
    }
}

void print_threads(){
    std::sort(target_tids.begin(),target_tids.end());
    printf("now threads:");
    for (int i=0; i<target_tids.size(); ++i){
        printf("%d ",target_tids[i]);
    }
    printf("\n");
    printf("threads_count:%d,target_tids.size():%lu\n",tids_count,target_tids.size());
}

void getNameByPid(pid_t pid, char *task_name) {
    char proc_pid_path[BUF_SIZE];
    char buf[BUF_SIZE];

    sprintf(proc_pid_path, "/proc/%d/status", pid);
    FILE* fp = fopen(proc_pid_path, "r");
    if(NULL != fp){
        if( fgets(buf, BUF_SIZE-1, fp)== NULL ){
            fclose(fp);
        }
        fclose(fp);
        sscanf(buf, "%*s %s", task_name);
    }
}

void get_tids(const pid_t pid)
{
    char     dirname[64];
    DIR     *dir;

    snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid);
    printf("dirname: %s\n",dirname);
    dir = opendir(dirname);
    
    while (1) {
        struct dirent *ent;
        int            value;
        char           dummy;

        ent = readdir(dir);
        if (!ent)
            break;
    #ifdef DEBUG
        printf("name: %s\n",ent->d_name);
    #endif
        /* Parse TIDs. Ignore non-numeric entries. */
        if (sscanf(ent->d_name, "%d%c", &value, &dummy) != 1)
            continue;

        /* Ignore obviously invalid entries. */
        if (value < 1)
            continue;

        target_tids.push_back(value);
        enter_or_leave[value]=ENTER;tids_count++;
    }
    closedir(dir);
}

void print_status(char* tag,pid_t wait_pid,int status){
    if (WIFSTOPPED(status))
    {
        printf("WIFSTOPPED %s %d recvied signal %d\n",tag, wait_pid, WSTOPSIG(status));
    }
    if (WIFSIGNALED(status))
    {
        printf("WIFSIGNALED %s %d recvied signal %d\n",tag, wait_pid, WTERMSIG(status));
    }
    if (WIFEXITED(status)) 
    {
        printf("WIFEXITED %s %d recvied signal %d\n",tag, wait_pid, WEXITSTATUS(status));
    }
}
