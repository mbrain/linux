#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>
#include <time.h>

#include "ptrace.h"

void ptrace_attach(pid_t target) {
	int waitpidstatus;

	if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_ATTACH) failed\n");
		exit(1);
	}
	if(waitpid(target, &waitpidstatus, WUNTRACED) != target) {
		fprintf(stderr, "waitpid(%d) failed\n", target);
		exit(1);
	}
}

void ptrace_detach(pid_t target) {
	if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_DETACH) failed\n");
		exit(1);
	}
}

void ptrace_getregs(pid_t target, struct REG_TYPE* regs) {
	if(ptrace(PTRACE_GETREGS, target, NULL, regs) == -1) {
		fprintf(stderr, "ptrace(PTRACE_GETREGS) failed\n");
		exit(1);
	}
}

void ptrace_cont(pid_t target) {
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 0;
	sleeptime->tv_nsec = 5000000;

	if(ptrace(PTRACE_CONT, target, NULL, NULL) == -1) {
		fprintf(stderr, "ptrace(PTRACE_CONT) failed\n");
		exit(1);
	}

	nanosleep(sleeptime, NULL);

	checktargetsig(target);
}

void ptrace_setregs(pid_t target, struct REG_TYPE* regs) {
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1) {
		fprintf(stderr, "ptrace(PTRACE_SETREGS) failed\n");
		exit(1);
	}
}

siginfo_t ptrace_getsiginfo(pid_t target) {
	siginfo_t targetsig;
	if(ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig) == -1) {
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO) failed\n");
		exit(1);
	}
	return targetsig;
}

void ptrace_read(int pid, unsigned long addr, void *vptr, int len) {
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		if(word == -1) {
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
			exit(1);
		}
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len) {
	int byteCount = 0;
	long word = 0;

	while (byteCount < len) {
		memcpy(&word, vptr + byteCount, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
		if(word == -1) {
			fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
			exit(1);
		}
		byteCount += sizeof(word);
	}
}

void checktargetsig(int pid) {
	siginfo_t targetsig = ptrace_getsiginfo(pid);
	if(targetsig.si_signo != SIGTRAP) {
		fprintf(stderr, "instead of expected SIGTRAP, target stopped with signal %d: %s\n", targetsig.si_signo, strsignal(targetsig.si_signo));
		fprintf(stderr, "sending process %d a SIGSTOP signal for debugging purposes\n", pid);
		ptrace(PTRACE_CONT, pid, NULL, SIGSTOP);
		exit(1);
	}
}

void restoreStateAndDetach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs) {
	ptrace_write(target, addr, backup, datasize);
	ptrace_setregs(target, &oldregs);
	ptrace_detach(target);
}
