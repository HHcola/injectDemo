#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <elf.h>
#include <fcntl.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <sys/mman.h>
#include <linux/binder.h>
#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) \
    LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif


/*
D/INJECT  ( 3992): [+] Target process returned from dlopen, return value=4901e5b8, pc=0
D/INJECT  ( 3992): sohandle addr = 0x4901e5b8
D/INJECT  ( 3992): [+] Calling dlsym in target process.
D/INJECT  ( 3992): [+] Target process returned from dlsym, return value=49a4d880, pc=0
D/INJECT  ( 3992): hook_entry_addr = 0x49a4d880
D/INJECT  ( 3992): [+] Calling hook_entry in target process.
D/INJECT  ( 3523): Hook success
D/INJECT  ( 3523): Start hooking
D/INJECT  ( 3523): Ioctl addr: 0x4005293d. New addr 0x49a4d0f0
D/INJECT  ( 3523): libbinder.so address = 0x400dc000
D/INJECT  ( 3523): out_addr = 40104cc8, out_size = 338
D/INJECT  ( 3523): Found old_ioctl in got
D/INJECT  ( 3523): page_size = 4096
D/INJECT  ( 3523): ~(page_size - 1) = -4096
D/INJECT  ( 3523): entry_page_start = 1074806784
D/INJECT  ( 3992): [+] Target process returned from hook_entry, return value=0, pc=0
 */


int call_count = 0;
   // 全局变量用以保存旧的ioctl地址，其实也可直接使用ioctl
int (*old_ioctl) (int __fd, unsigned long int __request, void * arg) = 0;

// 欲接替ioctl的新函数地址，其中内部调用了老的ioctl
int new_ioctl (int __fd, unsigned long int __request, void * arg)
{
    if ( __request == BINDER_WRITE_READ )
    {
        call_count++;
//        char value[PROPERTY_VALUE_MAX] = {'\0'};
        LOGD("call_count = %d", call_count);
//        snprintf(value, PROPERTY_VALUE_MAX, "%d", call_count);
//        property_set(PROP_IOCTL_CALL_COUNT, value);
    }

    int res = (*old_ioctl)(__fd, __request, arg);
    return res;
}


void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

#define LIBSF_PATH  "/system/lib/libbinder.so"
int hook_ioctlBuffers()
{
	old_ioctl = ioctl;
    LOGD("Ioctl addr: %p. New addr %p\n", ioctl, new_ioctl);

    // get addr map in progress
    void * base_addr = get_module_base(getpid(), LIBSF_PATH);
    LOGD("libbinder.so address = %p\n", base_addr);

    // open so file
    int fd;
    fd = open(LIBSF_PATH, O_RDONLY);
    if (-1 == fd) {
        LOGD("error\n");
        return -1;
    }

    // elf header info
    Elf32_Ehdr ehdr;
    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    // get section offsize
    unsigned long shdr_addr = ehdr.e_shoff;
    int shnum = ehdr.e_shnum;
    int shent_size = ehdr.e_shentsize;
    unsigned long stridx = ehdr.e_shstrndx;

    Elf32_Shdr shdr;
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);

    char * string_table = (char *)malloc(shdr.sh_size);
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);

    int i;
    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;

    for (i = 0; i < shnum; i++) {
        read(fd, &shdr, shent_size);
        if (shdr.sh_type == SHT_PROGBITS) {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
                    || strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = base_addr + shdr.sh_addr;
                out_size = shdr.sh_size;
                LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);

                for (i = 0; i < out_size; i += 4) {
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item  == old_ioctl) {
                        LOGD("Found old_ioctl in got\n");
                        got_found = 1;

                        LOGD("out_addr + i = %p", out_addr + i);
                        uint32_t page_size = getpagesize();
                        LOGD("page_size = %d", page_size);
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        LOGD("~(page_size - 1) = %d", ~(page_size - 1));
                        LOGD("entry_page_start = %p", entry_page_start);
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = new_ioctl;

                        break;
                    } else if (got_item == new_ioctl) {
                        LOGD("Already hooked\n");
                        break;
                    }
                }
                if (got_found)
                    break;
            }
        }
    }

    free(string_table);
    close(fd);
    return 0;
}

int hook_entry(char * a){
    LOGD("Hook success\n");
    LOGD("Start hooking\n");
    hook_ioctlBuffers();
    return 0;
}

