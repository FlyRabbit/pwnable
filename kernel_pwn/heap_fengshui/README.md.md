## Usage

- **Initialize the spraying strategy**

```
init_heap_spray(int _objectSize, char* _payload, int _payloadSize);
```

Specify the object size, the payload you want to copy to the kernelspace, and the size of payload.

- **Do a high-volume spraying**

```
do_heap_spray(int loop);
```

Specify how many rounds for spraying, for each round we spray 64 objects by default.

```
#define OBJS_EACH_ROUND 64
```

If you would like to change the number of objects that are sprayed each round, make a change on `default_objs_num`.

- **Do a precisely allocation**

```
do_spray(round, shade)
```

The first argument is the same as `do_heap_spray()`, the second argument `shade` determines whether increment the payload’s value by one for each round. if `shade `is `1`, the value of payload will increment by one for each round, for example, the payload is `AAAAAAAA` in the first round and will be `BBBBBBBB` in the second round. The payload will reset itself by different `do_spray()`. This might be helpful when you try to find how many objects you should free before putting the vulnerable object in the right place.

- **Free a object**

```
void do_free(u_int64_t val);
```

You can pass both the index of objects or the address the mutex lock which suspend on `fault_handler_thread()`. For example:

```
do_spray(10, 0);
do_free(0);
do_free(1);
do_free(2);
do_free(3);
do_free(4);
```

We first spray 10 objects on the heap, then free the first 5 objects. Please keep in mind, the free action does not straight invoke a system call to release an object but unlock the mutex lock in `fault_handler_thread()`, this step is asynchronous, making it sleep a little bit will be helpful. (eg. `usleep(500);`)

- **Modify the payload**

```
void **change_payload**(char* payload, int size);
```

Sometimes we want the change the payload. We pass the new payload as the first argument and follow by its size.

- **Customize spraying**

```
void **fork_and_spray**(int round, int objs_each_round, int shade, int new_page);
```

You may directly call `fork_and_spray()` to do more jobs.

The first argument is how many round you spray.

The second argument is how many objects are spraying for each round.

The third argument determines the shade feature.

The forth argument determines whether allocate new pages for pagefault or using the previous one.