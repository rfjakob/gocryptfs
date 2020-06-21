// See ../getdents/getdents.go for some info on why
// this exists.

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <pthread.h>

static pthread_mutex_t mutex;
static int sum;

struct up {
    pthread_mutex_t *my_mutex;
    pthread_mutex_t *other_mutex;
    int fd;
};

void *reader(void *arg) {
    struct up* up = (struct up*)arg;
    int fd = up->fd;
    char tmp[10000];
    while(1) {
        pthread_mutex_lock(up->my_mutex);
        int n = syscall(SYS_getdents64, fd, tmp, sizeof(tmp));
        if (n > 0) {
            printf("t%ld: n=%d\n", gettid(), n);
        } else {
            printf("t%ld: n=0 errno=%d total %d bytes\n", gettid(), errno, sum);
            if (n < 0) {
                exit(1);
            }
            pthread_mutex_unlock(up->other_mutex);
            break;
        }
        sum += n;
        pthread_mutex_unlock(up->other_mutex);
    }
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s PATH\n", argv[0]);
        printf("Run getdents(2) on PATH in a 100ms loop\n");
        exit(1);
    }

    const char *path = argv[1];

    for (int i = 1 ; ; i ++ ) {
        sum = 0;
        int fd = open(path, O_RDONLY);
        if (fd == -1) {
            perror("open");
            exit(1);
        }
        pthread_t reader1_thread, reader2_thread;
        pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER, m2 = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&m2);
        struct up up1, up2;
        up1.fd = fd;
        up1.my_mutex = &m1;
        up1.other_mutex = &m2;
        up2.fd = fd;
        up2.my_mutex = &m2;
        up2.other_mutex = &m1;
        pthread_create(&reader1_thread, NULL, reader, &up1);
        pthread_create(&reader2_thread, NULL, reader, &up2);
        pthread_join(reader1_thread, NULL);
        pthread_join(reader2_thread, NULL);
        close(fd);
        printf("---\n");
        usleep(100000);
    }
}
