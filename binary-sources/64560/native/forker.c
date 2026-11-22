/*
 * forker.c —— 制造 futex 阻塞，放大 sched_blocked_reason 事件量。
 *
 * 抓 KASLR 需要足够多的 sched_blocked_reason raw 记录；参考实现用预编译
 * forker，这里给一个可自行构建的最小替代（不依赖任何私有二进制）。
 *
 * 用法: forker [threads] [rounds]
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_THREADS 64
#define FUTEX_TIMEOUT_MS 50

static atomic_int g_word;
static int g_rounds = 30;

static long futex(volatile int *uaddr, int op, int val) {
    return syscall(SYS_futex, (int *)uaddr, op, val, NULL, NULL, 0);
}

static void *waiter(void *arg)
{
    (void)arg;
    for (int i = 0; i < g_rounds; i++) {
        int expect = 0;
        /* 值不匹配时立即 EAGAIN；匹配时进入 futex 等待并阻塞 */
        futex((volatile int *)&g_word, FUTEX_WAIT, expect);
        struct timespec ts = {0, FUTEX_TIMEOUT_MS * 1000000L};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int threads = argc > 1 ? atoi(argv[1]) : 2;
    if (argc > 2)
        g_rounds = atoi(argv[2]);
    if (threads < 1)
        threads = 1;
    if (threads > MAX_THREADS)
        threads = MAX_THREADS;
    if (g_rounds < 1)
        g_rounds = 1;

    pthread_t tid[MAX_THREADS];
    int started = 0;
    for (int i = 0; i < threads; i++) {
        if (pthread_create(&tid[i], NULL, waiter, NULL) != 0)
            break;
        started++;
    }

    for (int i = 0; i < g_rounds; i++) {
        atomic_store(&g_word, 1);
        futex((volatile int *)&g_word, FUTEX_WAKE, MAX_THREADS);
        struct timespec ts = {0, 2000000L};
        nanosleep(&ts, NULL);
        atomic_store(&g_word, 0);
    }

    for (int i = 0; i < started; i++)
        pthread_join(tid[i], NULL);
    printf("forker: threads=%d rounds=%d\n", started, g_rounds);
    return 0;
}
