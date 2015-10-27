#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>

int main(int argc, char *argv[], char*envp[])
{
    setuid(0);
    setgid(0);
    char* sh = "/system/bin/sh";
    char * const av[] = {sh, NULL};
    execve(sh, av, envp);

    return 0;
}
