#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <mntent.h>


void try_access(const char* mountpoint)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/.rw_test", mountpoint);
    FILE* f = fopen(path, "w");
    if (f != NULL) {
        int i;
        fprintf(f, "Write test OK: %s\n", mountpoint);
        fprintf(stderr, "Write test OK: %s\n", mountpoint);
        fclose(f);
        
        for (i = 0; i < 10; ++i) {
            snprintf(path, sizeof(path), 
                "/system/bin/sh -c \"sleep %d; echo slept %d OK >>%s/sleeptest.txt\"", 
                i, i, mountpoint);
            system(path);
        }
    }
}

static inited = 0;

void soinit(void)
{
    if (!inited) {
        inited = 1;
        fprintf(stderr, "SO LOADED\n");
        unsetenv("LD_PRELOAD");
        struct mntent *ent;
        FILE *mountsFile = fopen("/proc/mounts", "r");
        char dev[256];
        char mp[256];
        while (2 == fscanf(mountsFile, "%255s %255s %*s %*s %*s %*s", dev, mp)) {
            fprintf(stderr, "MOUNT: %s -> %s\n", dev, mp);
            try_access(mp);
        }
        fclose(mountsFile);
        exit(0);
    }
    for(;;) sleep(1);
}


//// Dummy functions!

void Java_com_honda_lib_securestorage_SecureAccess_doInit()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_doDeInit()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_open()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_close()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_closeAndDelete()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_write()
{
    soinit();
}

void Java_com_honda_lib_securestorage_SecureAccess_read()
{
    soinit();
}
