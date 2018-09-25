#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr) {
	asm("dec %esi");

	asm(
		"push %ecx \n"
		"call *%ebx \n"
		"mov %eax, %ebx \n"
		"int $3"
	);

	asm(
		"push $1 \n"
		"push %ebx \n"
		"call *%edi \n"
		"int $3"
	);

	asm(
		"push %ebx \n"
		"call *%esi"
	);

}

void injectSharedLibrary_end() {
}

int main(int argc, char** argv) {
	if(argc < 4) {
		usage(argv[0]);
		return 1;
	}

	char* command = argv[1];
	char* commandArg = argv[2];
	char* libname = argv[3];
	char* libPath = realpath(libname, NULL);

	char* processName = NULL;
	pid_t target = 0;

	if(!libPath) {
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if(!strcmp(command, "-n")) {
		processName = commandArg;
		target = findProcessByName(processName);
		if(target == -1) {
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}
		printf("targeting process \"%s\" with pid %d\n", processName, target);
	} else if(!strcmp(command, "-p")) {
		target = atoi(commandArg);
		printf("targeting process with pid %d\n", target);
	} else {
		usage(argv[0]);
		return 1;
	}

	int libPathLength = strlen(libPath) + 1;

	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid);

	long mallocAddr = getFunctionAddress("malloc");
	long freeAddr = getFunctionAddress("free");
	long dlopenAddr = getFunctionAddress("__libc_dlopen_mode");

	long mallocOffset = mallocAddr - mylibcaddr;
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;

	long targetLibcAddr = getlibcaddr(target);
	long targetMallocAddr = targetLibcAddr + mallocOffset;
	long targetFreeAddr = targetLibcAddr + freeOffset;
	long targetDlopenAddr = targetLibcAddr + dlopenOffset;

	struct user_regs_struct oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	long addr = freespaceaddr(target) + sizeof(long);
	regs.eip = addr;

	regs.ebx = targetMallocAddr;
	regs.edi = targetDlopenAddr;
	regs.esi = targetFreeAddr;
	regs.ecx = libPathLength;
	ptrace_setregs(target, &regs);


	size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;

	intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;

	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);

	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size - 1);
	newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	ptrace_cont(target);

	struct user_regs_struct malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	unsigned long targetBuf = malloc_regs.eax;
	if(targetBuf == 0) {
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	ptrace_write(target, targetBuf, libPath, libPathLength);

	ptrace_cont(target);

	struct user_regs_struct dlopen_regs;
	memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &dlopen_regs);
	unsigned long long libAddr = dlopen_regs.eax;

	if(libAddr == 0) {
		fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", libname);
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	if(checkloaded(target, libname)) {
		printf("\"%s\" successfully injected\n", libname);
	} else {
		fprintf(stderr, "could not inject \"%s\"\n", libname);
	}

	ptrace_cont(target);
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);

	return 0;
}
