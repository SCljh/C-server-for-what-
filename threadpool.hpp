//
// Created by acmery on 2020/6/29.
//

#ifndef TINYSERVER_THREADPOOL_HPP
#define TINYSERVER_THREADPOOL_HPP

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <list>

#include <pthread.h>

class ThreadPool {
private:
    struct NWORKER {
        pthread_t threadid;
        bool terminate;
        int isWorking;
        ThreadPool *pool;
    } *m_workers;

public:
    struct NJOB {
        void (*func)(void *arg);     //任务函数
        void *user_data;
    };

    //线程池初始化
    //numWorkers:线程数量
    ThreadPool(int numWorkers, int max_jobs);

    //销毁线程池
    ~ThreadPool();

    //向线程池中添加任务
    bool addJob(NJOB *job);

    //面向用户的添加任务
    int pushJob(void (*func)(void *data), void *arg);

    static void *run(void *arg);

    void threadLoop(void *arg);

private:
    std::list<NJOB *> m_jobs_list;
    int m_max_jobs;
    int m_sum_thread;
    int m_free_thread;
    pthread_cond_t m_jobs_cond;           //线程条件等待
    pthread_mutex_t m_jobs_mutex;         //为任务加锁防止一个任务被两个线程执行
};



#endif //TINYSERVER_THREADPOOL_HPP
