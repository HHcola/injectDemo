#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>
#include <assert.h>

#if defined(__i386__)
#define pt_regs         user_regs_struct
#endif

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) \
    LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

/**
 * #define PTRACE_TRACEME 0 // 将当前被跟踪的进程切换到停止状态,对于每一个进程，PTRACE_TRACEME 只能被调用一次
 *
#define PTRACE_PEEKTEXT 1
#define PTRACE_PEEKDATA 2
//PTRACE_PEEKTEXT and PTRACE_PEEKDATA(read) 分别从代码区和正被调试进程的地址空间区读取机器字。在许多当代的平台中，这两个指令是等价的。 ptrace 函数接收目标地址 addr ，并返回读到的结果。
#define PTRACE_PEEKUSR 3
// 从USER区域中读取一个字节，pid表示被跟踪的子进程，
 * USER区域地址由addr给出，data为用户变量地址用于返回读到的数据。
 * USER结构为core文件的前面一部分，它描述了进程中止时的一些状态，
 * 如：寄存器值，代码、数据段大小，代码、数据段开始地址等。
 * 在Linux（i386）中通过PTRACE_PEEKUSER和PTRACE_POKEUSR可以访问USER结构的数据有寄存器和调试寄存器
 *
 *
#define PTRACE_POKETEXT 4
#define PTRACE_POKEDATA 5
// PTRACE_POKETEXT and PTRACE_POKEDATA(write) 将由 data 传入的机器字写入 addr 所指定的地址
 *
#define PTRACE_POKEUSR 6
// 往USER区域中写入一个字节，pid表示被跟踪的子进程，USER区域地址由addr给出，data为需写入的数据


#define PTRACE_CONT 7
//  PTRACE_CONT and PTRACE_SYSCALL 继续进程标志为 pid 的被调试进程的执行，而不中断与调试器进程的通信。如果 addr == 0 ，
 * 从上次停止的地址继续执行；否则，从指定的地址继续执行。参数 data 指定发送到被调试进程的信号数量（零说明没有信号
 *
#define PTRACE_KILL 8
// 将 sigkill 发送到被调试进程，以终止其执行

#define PTRACE_SINGLESTEP 9
// 标志为 pid 的进程的单步执行，即执行下一条机器指令并切换为停止状态

#define PTRACE_ATTACH 0x10
// PTRACE_ATTACH 将进程标志为 pid 的运行进程切换为停止状态，在这种情形下，调试器进程成为“父进程”。
 * 其他的所有参数都被忽略。进程必须具有与调试进程相同的用户标志（ UID ），并且不能是 setuid/setduid 进程（否则就要用 root 来调试）。
 * 它会向子进程发送SIGSTOP信号，于是我们可以察看和修改子进程，然后使用 ptrace( PTRACE_DETACH, …)来使子进程继续运行下去


#define PTRACE_DETACH 0x11
// 停止进程标志为 pid 进程（由 PTRACE_ATTACH 和 PTRACE_TRACEME指定）的调试，并继续其常态运行。其他的所有参数都被忽略

#define PTRACE_SYSCALL 24


#define PTRACE_GETREGS 12
//  PTRACE_GETREGS and PTRACE_GETFPREGS将一般用途寄存器、段寄存器和调试寄存器的值读入到地址由 addr 指针所指定的调试器进程的内存区中。寄存器结构的描述放在头文件
 *
#define PTRACE_SETREGS 13
// PTRACE_SETREGS and PTRACE_SETFPREGS 通过拷贝由addr 指针所指定的内存区域的内容来设置被调试 进程 的寄存器的值
#define PTRACE_GETFPREGS 14
#define PTRACE_SETFPREGS 15


#define PTRACE_SETOPTIONS 0x4200
#define PTRACE_GETEVENTMSG 0x4201
#define PTRACE_GETSIGINFO 0x4202
#define PTRACE_SETSIGINFO 0x4203

 */
int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for (i = 0; i < j; i ++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

/*
Func : 将size字节的data数据写入到pid进程的dest地址处
@param dest: 目的进程的栈地址
@param data: 需要写入的数据的起始地址
@param size: 需要写入的数据的大小，以字节为单位
*/
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    //很巧妙的联合体，这样就可以方便的以字节为单位写入4字节数据，再以long为单位ptrace_poketext到栈中
    //一个页的大小 4096字节，是4字节的整数倍
    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4; // 剩余不足4个字节，单个写入，最大限度保持原虚拟内存数据

    laddr = data;

    for (i = 0; i < j; i ++) { // 4字节为单位进行数据写入
        memcpy(d.chars, laddr, 4);
        // PTRACE_POKETEXT 往内存地址中写入一个字节。pid表示被跟踪的子进程，内存地址由addr给出，data为所要写入的数据
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest  += 4;
        laddr += 4;
    }

    //为了最大程度的保持原栈的数据，先读取dest的long数据，然后只更改其中的前remain字节，再写回
    if (remain > 0) {
        // PTRACE_PEEKTEXT 从内存地址中读取一个字节，pid表示被跟踪的子进程，内存地址由addr给出，data为用户变量地址用于返回读到的数据。在Linux（i386）中用户代码段与用户数据段重合所以读取代码段和数据段数据处理是一样的
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    /*
     * 总结一下ptrace_call_wrapper，它的完成两个功能：
     * 一是调用ptrace_call函数来执行指定函数，执行完后将子进程挂起；
     * 二是调用ptrace_getregs函数获取所有寄存器的值，主要是为了获取r0即函数的返回值
     */
    return 0;
}

/**
 #define ARM_cpsr uregs[16] 程序状态寄存器
#define ARM_pc uregs[15] 程序计数器下一条将要执行的指令
#define ARM_lr uregs[14] 寄存器，返回地址link
#define ARM_sp uregs[13] 栈指针
#define ARM_ip uregs[12] 暂存sp没什么大作用
#define ARM_fp uregs[11] 栈帧zhizhen
#define ARM_r10 uregs[10]
#define ARM_r9 uregs[9]
#define ARM_r8 uregs[8]
#define ARM_r7 uregs[7]
#define ARM_r6 uregs[6]
#define ARM_r5 uregs[5]
#define ARM_r4 uregs[4]
#define ARM_r3 uregs[3]
#define ARM_r2 uregs[2]
#define ARM_r1 uregs[1]
#define ARM_r0 uregs[0]
#define ARM_ORIG_r0 uregs[17]

 */
#if defined(__arm__)
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
    uint32_t i;
    for (i = 0; i < num_params && i < 4; i ++) {
        regs->uregs[i] = params[i];
    }

    //
    // push remained params onto stack
    //
    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr; //将寄存器的值设为目标函数的地址
    if (regs->ARM_pc & 1) { // 进行指令集判断
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK; // #define CPSR_T_MASK     ( 1u << 5 ) 寄存器状态
    }

    regs->ARM_lr = 0; //设置子程序的返回地址为空，以便函数执行完后，返回到null地址，产生SIGSEGV错误


    /*
     *Ptrace_setregs就是将修改后的regs写入寄存器中，然后调用ptrace_continue来执行我们指定的代码
     */
    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    /* WUNTRACED告诉waitpid，如果子进程进入暂停状态，那么就立即返回。如果是被ptrace的子进程，那么即使不提供WUNTRACED参数，也会在子进程进
     * 入暂停状态的时候立即返回。对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发
     * 生错误。这里的0xb7f就表示子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV)，它表示试图访问未分配给自己的内存, 或试图往没有写权限的
     * 内存地址写数据。那么什么时候会发生这种错误呢？显然，当子进程执行完注入的函数后，由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV了！
     */


    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    //这个循环是否必须我还不确定。因为目前每次ptrace_call调用必定会返回0xb7f，不过在这也算是增加容错性吧~
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

   /*
    * 通过看ndk的源码sys/wait.h以及man waitpid可以知道这个0xb7f的具体作用。首先说一下stat的值：
    * 高2字节用于表示导致子进程的退出或暂停状态信号值，低2字节表示子进程是退出(0x0)还是暂停(0x7f)状态。0xb7f就表示子进程为暂停状态，导致它暂停的信号量为11即sigsegv错误
    */
    return 0;
}

#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->esp -= (num_params) * sizeof(long) ;
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->eip = addr;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#else
#error "Not supported"
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
	// 读取寄存器值，pid表示被跟踪的子进程，data为用户变量地址用于返回读到的数据。此功能将读取所有17个基本寄存器的值
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
	// 设置寄存器值，pid表示被跟踪的子进程，data为用户数据地址。此功能将设置所有17个基本寄存器的值
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
	// 继续执行。pid表示被跟踪的子进程，signal为0则忽略引起调试进程中止的信号，若不为0则继续处理信号signal。
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
	// 跟踪指定pid进程。pid表示被跟踪进程。被跟踪进程将成为当前进程的子进程，并进入中止状态。调试器进程成为"父进程"
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        DEBUG_PRINT("ptrace_attach error : %d", errno);
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED); // WUNTRACED 若子进程进入暂停状态，则马上返回，但子进程的结束状态不予以理会

    return 0;
}

int ptrace_detach(pid_t pid)
{
	// 结束跟踪。 pid表示被跟踪的子进程。结束跟踪后被跟踪进程将继续执行
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

/**
 * 获取模块地址
 */
void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);// 获取self内存maps
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid); // 获取pid进程内存映射maps
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) { // 搜索字符串
                pch = strtok( line, "-" ); // 分解字符串
                addr = strtoul( pch, NULL, 16 ); // 字符串转换为长整型

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    DEBUG_PRINT("[+] get_remote_addr: local[%x], remote[%x], local_addr[%x]\n", local_handle, remote_handle, local_addr);

    // 获取mmap在目标函数中的偏移地址，mmap在libc.so动态库中
    /**
     * "/proc/self/maps" 是获取当前进程的虚拟地址映射表
     * 查看正在运行的动态链接的程序中，某个动态库中函数的虚拟地址
     * 方法很简单，首先确定，你需要查看的函数，在哪个动态库中，并且确定该函数相对于该动态库的相对地址。
     * 其次，在程序运行期间，查看程序的映射表，找到动态库的加载地址。最后将这两个地址相加，就是你要的库函数在运行时的虚拟地址
     *
     * 1. (void *)((uint32_t)local_addr - (uint32_t)local_handle 获取mmap在inject进程中的相对地址
     * 2. remote_handle为libc.so在target_pid偏移地址
     * 1 + 2结果是mmap在target_pid中的虚拟地址
     */
    void * ret_addr = (void *)((uint32_t)local_addr - (uint32_t)local_handle + (uint32_t)remote_handle);

#if defined(__i386__)
    if (!strcmp(module_name, libc_path)) {
        ret_addr += 2;
    }
#endif
    return ret_addr;
}

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

long ptrace_retval(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}

long ptrace_ip(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

/**
 * 调用mmap函数，在目标进程中为libxxx.so分配内存
 */
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
    DEBUG_PRINT("[+] Target process returned from %s, return value=%x, pc=%x \n",
            func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
        _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;
    long parameters[10];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

    /* call mmap */
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    // 从寄存器中获取mmap函数的返回值，即申请的内存首地址：
//    map_base = ptrace_ip(&regs);
    map_base = ptrace_retval(&regs);
    DEBUG_PRINT("map_base addr = %p\n", map_base);

    // 依次获取linker中dlopen、dlsym、dlclose、dlerror函数的地址:
    // void * dlopen( const char * pathname, int mode );  RTLD_LAZY 暂缓决定，等有需要时再解出符号
    // RTLD_NOW 立即决定，返回前解除所有未决定的符号。
    // RTLD_LOCAL
    // RTLD_GLOBAL 允许导出符号
    // RTLD_GROUP
    // RTLD_WORLD 打开一个动态链接库
    //

    // void*dlsym(void* handle,const char* symbol)  根据动态链接库操作句柄与符号，返回符号对应的地址
    // 使用这个函数不但可以获取函数地址，也可以获取变量地址

    // dlclose用于关闭指定句柄的动态链接库，只有当此动态链接库的使用计数为0时,才会真正被系统卸载。
    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror );

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    DEBUG_PRINT("library path = %s\n", library_path);
    // 调用dlopen函数：
    /**
     * ①将要注入的so名写入前面mmap出来的内存
     * ②写入dlopen代码
     * ③执行dlopen("libxxx.so", RTLD_NOW ! RTLD_GLOBAL) RTLD_NOW之类的参数作用可参考：http://baike.baidu.com/view/2907309.htm?fr=aladdin
     * ④取得dlopen的返回值，存放在sohandle变量中
     */
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    // 从寄存器中获取libxxx.so句柄值
//    void * sohandle = ptrace_ip(&regs);
    void * sohandle = ptrace_retval(&regs); // 返回动态库可操作句柄

    DEBUG_PRINT("sohandle addr = %p\n", sohandle);


    // 调用dlsym函数：
#define FUNCTION_NAME_ADDR_OFFSET       0x100 //为function name另找一块区域  在这个区域里保存率function_name这个字符串常量
    // 但是这个地址如何找呢？随意去一个偏移量吗？这个偏移量需要大于libsize，但是会不会破坏原有的虚拟内存数据？
    // 这里应该对修改的区域进行还原
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;

    // 但是map_base + FUNCTION_NAME_ADDR_OFFSE就确定为hook_entry的地址吗？？不是，而是自己另外开辟的内存段，用来存储字符串
    // 这个函数获取function_name在so开辟VMA中的地址：returning the address where that symbol is loaded into memory
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

//    void * hook_entry_addr = ptrace_ip(&regs);
    void * hook_entry_addr = ptrace_retval(&regs);
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200 // 同上，在一块新的内存中开辟一块，用来保存输入参数字符串
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    // 调用hook_entry函数：
    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    printf("Press enter to dlclose and detach\n");
    getchar(); // 屏蔽enter按键
    parameters[0] = sohandle;

    // 调用dlclose关闭lib:
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;

    /* restore */
    // 恢复现场并退出ptrace:
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}

/*
D/INJECT  (13877): [+] Injecting process: 10562
D/INJECT  (13877): [+] get_remote_addr: local[40132000], remote[40117000], local_addr[40092558]
D/INJECT  (13877): [+] Remote mmap address: 40077558
D/INJECT  (13877): [+] Calling mmap in target process.
D/INJECT  (13877): [+] Target process returned from mmap, return value=0, pc=4027f57c
D/INJECT  (13877): map_base addr = 0x4027f57c
D/INJECT  (13877): [+] get_remote_addr: local[40024000], remote[400a1000], local_addr[40029c79]
D/INJECT  (13877): [+] get_remote_addr: local[40024000], remote[400a1000], local_addr[40029be5]
D/INJECT  (13877): [+] get_remote_addr: local[40024000], remote[400a1000], local_addr[40029b25]
D/INJECT  (13877): [+] get_remote_addr: local[40024000], remote[400a1000], local_addr[40029b15]
D/INJECT  (13877): [+] Get imports: dlopen: 400a6c79, dlsym: 400a6be5, dlclose: 400a6b25, dlerror: 400a6b15
D/INJECT  (13877): library path = /data/data/com.example.hellojni/libhello.so
D/INJECT  (13877): [+] Calling dlopen in target process.
D/INJECT  (13877): [+] Target process returned from dlopen, return value=400bb154, pc=0
D/INJECT  (13877): sohandle addr = 0x400bb154
D/INJECT  (13877): [+] Calling dlsym in target process.
D/INJECT  (13877): [+] Target process returned from dlsym, return value=41a93c0c, pc=0
D/INJECT  (13877): hook_entry_addr = 0x41a93c0c
D/INJECT  (13877): [+] Calling hook_entry in target process.
D/INJECT  (10562): Hook success, pid = 10562
D/INJECT  (10562): Hello I'm parameter!
D/INJECT  (13877): [+] Target process returned from hook_entry, return value=0, pc=0
D/INJECT  (13877): [+] Calling dlclose in target process.
D/INJECT  (13877): [+] Target process returned from dlclose, return value=400bb154, pc=40029b24
 */
int inject_remote_process_samsung(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
        _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;
    long parameters[10];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

    /* call mmap */
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    // 从寄存器中获取mmap函数的返回值，即申请的内存首地址：
    map_base = ptrace_ip(&regs);
    DEBUG_PRINT("map_base addr = %p\n", map_base);

    // dlclose用于关闭指定句柄的动态链接库，只有当此动态链接库的使用计数为0时,才会真正被系统卸载。
    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror );

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    DEBUG_PRINT("library path = %s\n", library_path);
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    // 从寄存器中获取libxxx.so句柄值
    void * sohandle = ptrace_retval(&regs);

    DEBUG_PRINT("sohandle addr = %p\n", sohandle);


    // 调用dlsym函数：
#define FUNCTION_NAME_ADDR_OFFSET       0x200 //为function name另找一块区域
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;

    // 但是map_base + FUNCTION_NAME_ADDR_OFFSE就确定为hook_entry的地址吗？？
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    void * hook_entry_addr = ptrace_retval(&regs);
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x300
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    // 调用hook_entry函数：
    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    parameters[0] = sohandle;
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;

    /* restore */
    // 恢复现场并退出ptrace:
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}

int hookSystemService() {
    pid_t target_pid;
    target_pid = find_pid_of("system_server");
    if (-1 == target_pid) {
    	LOGD("Can't find the process\n");
        return -1;
    }
//    return inject_remote_process(target_pid, "/data/data/com.example.hellojni/lib/libmyioctl.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
    return inject_remote_process_samsung(target_pid, "/data/data/com.example.hellojni/libmyioctl.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
}

int hookSurfaceflinger() {
    pid_t target_pid;
    target_pid = find_pid_of("/system/bin/surfaceflinger");
    if (-1 == target_pid) {
    	LOGD("Can't find the process\n");
        return -1;
    }
    return inject_remote_process(target_pid, "/data/data/com.example.hellojni/lib/libhello.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
//    inject_remote_process_samsung(target_pid, "/data/data/com.example.hellojni/libhello.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
}
/////////////////////////////////JNI/////////////////////////////////////////

// 实现自定义JNI_OnLoad JNI_OnUnload
JNIEXPORT jstring JNICALL native_fromJNI( JNIEnv * env,
		                                  jclass class)
{

	LOGD("from JNI IN c Native");
	pid_t target_pid;
//	target_pid = find_pid_of("/system/bin/servicemanager");
	target_pid = find_pid_of("/system/bin/surfaceflinger");
	LOGD("target_pid = %d",target_pid);
//	int success = inject_remote_process( target_pid, "/data/libhello.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
	int success = inject_remote_process( target_pid, "/data/data/com.example.hellojni/lib/libhello.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );

	if(success!=0)
		return (*env)->NewStringUTF(env, "fail");
	else
		return (*env)->NewStringUTF(env, "success");
}

#define JNIREC_CLASS "com/example/hellojni/HelloJni"  // 指定要注册的类

/**
 * Table of methods associated with a single class.
 */
static JNINativeMethod gMethods[] = {
		{"fromJNI" , "()Ljava/lang/String;", (void *)native_fromJNI},
};


/**
 * register several native methods for one class
 */
static int registerNativeMethods(JNIEnv *env, const char * className,
		  JNINativeMethod * gMethods, int numMethods)
{

	jclass class;
	class = (*env)->FindClass(env, className);
	if (class == NULL ) {
		LOGD("FindClass Failed !!!");
		return JNI_FALSE;
	}

	if ((*env)->RegisterNatives(env, class, gMethods, numMethods) < 0 ) {
		LOGD("Register Natives Failed !!!!!");
		return JNI_FALSE;
	}

	LOGD("Register Natives Succes");
	return JNI_TRUE;
}

/**
 * Register native methods for all classes we know about.
 */
static int registerNatives(JNIEnv * env)
{
	if (!registerNativeMethods(env, JNIREC_CLASS, gMethods, sizeof(gMethods)/ sizeof(gMethods[0]))) {
		return JNI_FALSE;
	}

	return JNI_TRUE;
}

/*
* Set some test stuff up.
*
* Returns the JNI version on success, -1 on failure.
*/
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env = NULL;
	jint result = -1;

	LOGD("JNI_OnLoad!!");

	if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK) {
		LOGD("GetEnv Failed !!!");
		return -1;
	}
	assert(env != NULL);

	if (!registerNatives(env)) {//注册
		return -1;
	}
	/* success -- return valid version number */
	result = JNI_VERSION_1_4;

	return result;
}

JNIEXPORT jint JNICALL JNI_UnOnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env = NULL;
	jint result = -1;

	LOGD("JNI_UnOnLoad!!");
	return result;
}


int main(int argc, char** argv) {
//	return hookSurfaceflinger();
	return hookSystemService();
}
