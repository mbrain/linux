#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "utils.h"

pid_t findProcessByName(char* processName) {
	if(processName == NULL) {
		return -1;
	}

	struct dirent *procDirs;

	DIR *directory = opendir("/proc/");

	if (directory) {
		while ((procDirs = readdir(directory)) != NULL) {
			if (procDirs->d_type != DT_DIR)
				continue;

			pid_t pid = atoi(procDirs->d_name);

			int exePathLen = 10 + strlen(procDirs->d_name) + 1;
			char* exePath = malloc(exePathLen * sizeof(char));

			if(exePath == NULL) {
				continue;
			}

			sprintf(exePath, "/proc/%s/exe", procDirs->d_name);
			exePath[exePathLen-1] = '\0';

			char* exeBuf = malloc(PATH_MAX * sizeof(char));
			if(exeBuf == NULL) {
				free(exePath);
				continue;
			}
			ssize_t len = readlink(exePath, exeBuf, PATH_MAX - 1);

			if(len == -1) {
				free(exePath);
				free(exeBuf);
				continue;
			}

			exeBuf[len] = '\0';

			char* exeName = NULL;
			char* exeToken = strtok(exeBuf, "/");
			while(exeToken) {
				exeName = exeToken;
				exeToken = strtok(NULL, "/");
			}

			if(strcmp(exeName, processName) == 0) {
				free(exePath);
				free(exeBuf);
				closedir(directory);
				return pid;
			}

			free(exePath);
			free(exeBuf);
		}

		closedir(directory);
	}

	return -1;
}

long freespaceaddr(pid_t pid) {
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char str[20];
	char perms[5];
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);

		if(strstr(perms, "x") != NULL) {
			break;
		}
	}
	fclose(fp);
	return addr;
}

long getlibcaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char perms[5];
	char* modulePath;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, "libc-") != NULL) {
			break;
		}
	}
	fclose(fp);
	return addr;
}

int checkloaded(pid_t pid, char* libname) {
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char perms[5];
	char* modulePath;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		exit(1);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if(strstr(line, libname) != NULL) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

long getFunctionAddress(char* funcName) {
	void* self = dlopen("libc.so.6", RTLD_LAZY);
	void* funcAddr = dlsym(self, funcName);
	return (long)funcAddr;
}

unsigned char* findRet(void* endAddr) {
	unsigned char* retInstAddr = endAddr;
	while(*retInstAddr != INTEL_RET_INSTRUCTION) {
		retInstAddr--;
	}
	return retInstAddr;
}

void usage(char* name) {
	printf("usage: %s [-n process-name] [-p pid] [library-to-inject]\n", name);
}
