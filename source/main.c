/*****************************************************************
*
* ============== Game Decrypt for 4.05 - AlFaMoDz ================
*
*	Thanks to:
*	-Specter for his kernel exploit / Code Execution method
*	-IDC for his patches
*	- WildCard File Decrypt Port
*	-Grass Skeu for his original Dump File on 1.76 that most
*	of this code came from, thanks Skeu!
*
******************************************************************/

#include "ps4.h"
#include "elf64.h"
#include "elf_common.h"

// Defines

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */

#define TRUE 1
#define FALSE 0

#define X86_CR0_WP (1 << 16)

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

int sock;

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}


static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};



struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct kpayload_args{
	uint64_t user_arg;
};

struct kdump_args{
    	uint64_t argArrayPtr;
};


// dump file functions

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
} SegmentBufInfo;


void hexdump(uint8_t *raw, size_t size) {
    for (int i = 1; i <= size; i += 1) {
        printfsocket("%02X ", raw[i - 1]);
        if (i % 16 == 0) {
            printfsocket("\n");
        }
    }
}


void print_phdr(Elf64_Phdr *phdr) {
    printfsocket("=================================\n");
    printfsocket("     p_type %08x\n", phdr->p_type);
    printfsocket("     p_flags %08x\n", phdr->p_flags);
    printfsocket("     p_offset %016llx\n", phdr->p_offset);
    printfsocket("     p_vaddr %016llx\n", phdr->p_vaddr);
    printfsocket("     p_paddr %016llx\n", phdr->p_paddr);
    printfsocket("     p_filesz %016llx\n", phdr->p_filesz);
    printfsocket("     p_memsz %016llx\n", phdr->p_memsz);
    printfsocket("     p_align %016llx\n", phdr->p_align);
}


void dumpfile(char *name, uint8_t *raw, size_t size) {
    FILE *fd = fopen(name, "wb");
    if (fd != NULL) {
        fwrite(raw, 1, size, fd);
        fclose(fd);
    }
    else {
        printfsocket("dump err.\n");
    }
}


int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out) {
    uint64_t realOffset = (index << 32) | offset;
    uint8_t *addr = (uint8_t*)mmap(0, size, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
    if (addr != MAP_FAILED) {
        memcpy(out, addr, size);
        munmap(addr, size);
        return TRUE;
    }
    else {
        printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
        return FALSE;
    }
}



int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                // printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
                // printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
    printfsocket("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];
        // print_phdr(phdr);

        if (phdr->p_filesz > 0 && phdr->p_type != 0x6fffff01) {
            if (!is_segment_in_other_segment(phdr, i, phdrs, num)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;

                // printfsocket("seg buf info %d -->\n", segindex);
                // printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
                // printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}


void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
    FILE *sf = fopen(saveFile, "wb");
    if (sf != NULL) {
        size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
        printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
        fwrite(ehdr, elfsz, 1, sf);

        for (int i = 0; i < segBufNum; i += 1) {
            printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
            uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
            memset(buf, 0, segBufs[i].bufsz);
            if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
                fseek(sf, segBufs[i].fileoff, SEEK_SET);
                fwrite(buf, segBufs[i].bufsz, 1, sf);
            }
            free(buf);
        }
        fclose(sf);
    }
    else {
        printfsocket("fopen %s err : %s\n", saveFile, strerror(errno));
    }
}


void dumpSelfPatch(void){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	printfkernel("applying patches\n");

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// patch allowed to mmap self *thanks to IDC
	*(uint8_t*)(kernel_base + 0x31EE40) = 0x90; //0x0F
	*(uint8_t*)(kernel_base + 0x31EE41) = 0xE9; //0x84
	*(uint8_t*)(kernel_base + 0x31EF98) = 0x90; //0x74
	*(uint8_t*)(kernel_base + 0x31EF99) = 0x90; //0x0F

	// restore write protection

	writeCr0(cr0);

	printfkernel("kernel patched\n");

}

void dumpSelfPatchOrig(void){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
		int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);
	printfkernel("restoring kernel\n");

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// restore kernel 
	*(uint8_t*)(kernel_base + 0x31EE40) = 0x0F; //0x0F
	*(uint8_t*)(kernel_base + 0x31EE41) = 0x84; //0x84
	*(uint8_t*)(kernel_base + 0x31EF98) = 0x74; //0x74
	*(uint8_t*)(kernel_base + 0x31EF99) = 0x0F; //0x0F

	// restore write protection

	writeCr0(cr0);

	printfkernel("kernel restored\n");

}


void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	
	// patch for decrypting

	printfsocket("applying patches\n");
	syscall(11,dumpSelfPatch);

    int fd = open(selfFile, O_RDONLY,0);
    if (fd != -1) {
        void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printfsocket("mmap %s : %p\n", selfFile, addr);

            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
            printfsocket("ehdr : %p\n", ehdr);

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
            printfsocket("phdrs : %p\n", phdrs);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
            printfsocket("dump completed\n");

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else {
            printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
        }
    }
    else {
        printfsocket("open %s err : %s\n", selfFile, strerror(errno));
    }
	// set it back to normal

	printfsocket("restoring kernel\n");
	syscall(11,dumpSelfPatchOrig);
}



int kpayload(struct thread *td){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	// resolve kernel functions

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	uint16_t *securityFlags = (uint64_t *)(kernel_base+0x2001516);
	*securityFlags = *securityFlags & ~(1 << 15);

	// specters debug settings patchs

	*(char *)(kernel_base + 0x186b0a0) = 0; 
	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;

	// restore write protection

	writeCr0(cr0);

	// Say hello and put the kernel base just for reference

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");
	printfkernel("kernel base is:0x%016llx\n", kernel_base);


	return 0;
}


int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 64);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));


	printfsocket("connected\n");

	// jailbreak / debug settings etc
	syscall(11,kpayload,td);

	// decrypt
	printfsocket("decrypting\n");

	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/eboot.bin", "/mnt/usb0/eboot.bin");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libc.prx", "/mnt/usb0/libc.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceAudioLatencyEstimation.prx", "/mnt/usb0/libSceAudioLatencyEstimation.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceFace.prx", "/mnt/usb0/libSceFace.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceFaceTracker.prx", "/mnt/usb0/libSceFaceTracker.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceFios2.prx", "/mnt/usb0/libSceFios2.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceFios2_debug.prx", "/mnt/usb0/libSceFios2_debug.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceHand.prx", "/mnt/usb0/libSceHand.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceHandTracker.prx", "/mnt/usb0/libSceHandTracker.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceHeadTracker.prx", "/mnt/usb0/libSceHeadTracker.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceJobManager.prx", "/mnt/usb0/libSceJobManager.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceJobManager_debug.prx", "/mnt/usb0/libSceJobManager_debug.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceNpToolkit2.prx", "/mnt/usb0/libSceNpToolkit2.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceS3DConversion.prx", "/mnt/usb0/libSceS3DConversion.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_module/libSceSmart.prx", "/mnt/usb0/libSceSmart.prx");
	decrypt_and_dump_self("/mnt/sandbox/pfsmnt/CUSA00000-app0/sce_sys/about/right.sprx", "/mnt/usb0/right.sprx");

	// dont forget to close the socket
	sceNetSocketClose(sock);

    return 0;
}


