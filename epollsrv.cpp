#include "commen.h"


int main(int argc, char* argv[])
{
    signal(SIGPIPE, SIG_IGN);
    char buf[BUFSIZ];
    int clientCount = 0;
    if (argc != 2){
        cout << "use: " << argv[0] << " tor_port to start server." << endl;
        return 1;
    }
    try
    {
        TCPServer server(8001, "10.59.13.178");
        strcat(server.tor_port, argv[1]);
        int listenfd = server.getfd();
        // 将监听套接字注册到epoll
        server.epoll.addfd(server.getfd(), EPOLLIN, true);
        server.startCatch();
        while (true)
        {
            int nReady = server.epoll.wait();
            for (int i = 0; i < nReady; ++i) {
                // 如果是监听套接字发生了可读事件
                if (server.epoll.getEventOccurfd(i) == listenfd) {
                    int connectfd = accept(listenfd, NULL, NULL);
                    if (connectfd == -1)
                        err_exit("accept error");
                    cout << "accept success..." << endl;
                    cout << "clientCount = " << ++clientCount << endl;
                    setUnBlock(connectfd, true);
                    //创建一个client并加入server的clients中
                    TCPClient *client = new TCPClient(connectfd);
                    server.addClient(client);
                    //server.epoll.addfd(connectfd, EPOLLIN, true);
                    pthread_mutex_lock(&server.clients_mutex);
                    server.clients.push_back(client);
                    pthread_mutex_unlock(&server.clients_mutex);
                } else if (server.epoll.getEvents(i) & EPOLLIN) {
                    TCPClient *client = (TCPClient*)server.epoll.m_events[i].data.ptr;
                    memset(buf, 0, sizeof(buf));
                    if (client->read(&client->pcmd, sizeof(client->pcmd)) == 0) {
                        cerr << "client connect closed..." << endl;
                        // 将该套接字从epoll中移除
                        //TODO:fds
                        server.epoll.delfd(client->getfd());
                        delete client;
                        continue;
                    }
                    cout << "client->pcmd.type: " << client->pcmd.type << endl;
                    cout << "client->pcmd.len: " << client->pcmd.len << endl;
                    cout << "client->pcmd.msg: " << client->pcmd.msg << endl;
                    switch (client->pcmd.type){
                        case 0:
                            server.startTor(client);
                            break;
                        case 1:
                            server.stopTor(client);
                            break;
                        case 2:
                            server.getInfo(client);
                            break;
                    }
                } else if (server.epoll.getEvents(i) & EPOLLOUT){
                    TCPClient *client = (TCPClient*)server.epoll.m_events[i].data.ptr;
                    int send_size = send(client->getfd(), &client->pcmd.msg, client->pcmd.len, MSG_NOSIGNAL);
                    if (send_size <= 0){
                        cout << "client removed.." << endl;
                        server.delClient(client);
                    }
                    else {
                        cout << "send ok, msg: " << client->pcmd.msg << endl;
                        server.modClient(client);
                    }
                }
            }
        }
    }
    catch (const SocketException &e)
    {
        cerr << e.what() << endl;
        err_exit("TCPServer error");
    }
    catch (const EpollException &e)
    {
        cerr << e.what() << endl;
        err_exit("Epoll error");
    }
}
