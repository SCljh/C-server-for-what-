//
// Created by acmery on 2020/7/12.
//

ThreadPool::ThreadPool(int numWorkers, int max_jobs = 20) : m_sum_thread(numWorkers),
                                                            m_free_thread(numWorkers),
                                                            m_max_jobs(max_jobs) {   //numWorkers:线程数量
    if (numWorkers < 1 || max_jobs < 1) {
        perror("workers num error");
    }
    //初始化jobs_cond
    if (pthread_cond_init(&m_jobs_cond, NULL) != 0)
        perror("init m_jobs_cond fail\n");

    //初始化jobs_mutex
    if (pthread_mutex_init(&m_jobs_mutex, NULL) != 0)
        perror("init m_jobs_mutex fail\n");

    //初始化workers
    m_workers = new NWORKER[numWorkers];
    if (!m_workers) {
        perror("create workers failed!\n");
    }

    for (int i = 0; i < numWorkers; ++i) {

        m_workers[i].pool = this;

        int ret = pthread_create(&(m_workers[i].threadid), NULL, run, &m_workers[i]);
        if (ret) {
            delete[] m_workers;
            perror("create worker fail\n");
        }
        if (pthread_detach(m_workers[i].threadid)) {
            delete[] m_workers;
            perror("detach worder fail\n");
        }
        m_workers[i].terminate = 0;
    }
}

ThreadPool::~ThreadPool() {
    for (int i = 0; i < m_sum_thread; i++) {
        m_workers[i].terminate = 1;
    }
    pthread_mutex_lock(&m_jobs_mutex);
    pthread_cond_broadcast(&m_jobs_cond);
    pthread_mutex_unlock(&m_jobs_mutex);
    delete[] m_workers;
}

//向线程池中添加任务
bool ThreadPool::addJob(NJOB *job) {
    pthread_mutex_lock(&m_jobs_mutex);
    if (m_jobs_list.size() >= m_max_jobs) {
        pthread_mutex_unlock(&m_jobs_mutex);
        return false;
    }
    m_jobs_list.push_back(job);
    //唤醒休眠的线程
    pthread_cond_signal(&m_jobs_cond);
    pthread_mutex_unlock(&m_jobs_mutex);

}

//面向用户的添加任务
int ThreadPool::pushJob(void (*func)(void *), void *arg) {
    struct NJOB *job = (struct NJOB *) malloc(sizeof(struct NJOB));
    if (job == NULL) {
        perror("malloc");
        return -2;
    }

    memset(job, 0, sizeof(struct NJOB));

    std::memcpy(job->user_data, arg, sizeof(arg));
    job->func = func;

    addJob(job);

    return 1;
}

void *ThreadPool::run(void *arg) {
    NWORKER *worker = (NWORKER *) arg;
    worker->pool->threadLoop(arg);
}

void ThreadPool::threadLoop(void *arg) {
    NWORKER *worker = (NWORKER *) arg;
    while (1) {
        //线程只有两个状态：执行\等待
        pthread_mutex_lock(&m_jobs_mutex);
        while (m_jobs_list.size() == 0) {
            if (worker->terminate) break;
            pthread_cond_wait(&m_jobs_cond, &m_jobs_mutex);
        }
        if (worker->terminate) {
            pthread_mutex_unlock(&m_jobs_mutex);
            break;
        }
        struct NJOB *job = m_jobs_list.front();
        m_jobs_list.pop_front();

        pthread_mutex_unlock(&m_jobs_mutex);

        m_free_thread--;
        worker->isWorking = true;
        job->func(job->user_data);
        worker->isWorking = false;

        free(job->user_data);
        free(job);
    }

    free(worker);
    pthread_exit(NULL);
}