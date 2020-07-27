#include "Socket.h"

#define TOR_PORT 5000

TCPSocket::TCPSocket(): m_sockfd(-1) {}
TCPSocket::~TCPSocket()
{
    if (isValid())
        ::close(m_sockfd);
}

bool TCPSocket::create()
{
    if (isValid())
        return false;

    if ((m_sockfd = ::socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return false;
    return true;
}

bool TCPSocket::bind(unsigned short int port, const char *ip) const
{
    if (!isValid())
        return false;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip == NULL)
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else {
        addr.sin_addr.s_addr = inet_addr(ip);
    }
    if ( ::bind(m_sockfd, (const struct sockaddr *)&addr, sizeof(addr)) == -1 )
        return false;
    return true;
}
bool TCPSocket::listen(int backlog) const
{
    if (!isValid())
        return false;

    if ( ::listen(m_sockfd, backlog) == -1)
        return false;
    return true;
}
bool TCPSocket::accept(TCPSocket &clientSocket) const
{
    if (!isValid())
        return false;

    clientSocket.m_sockfd =
        ::accept(this->m_sockfd, NULL, NULL);
    if (clientSocket.m_sockfd == -1)
        return false;
    return true;
}

bool TCPSocket::connect(unsigned short int port, const char *ip) const
{
    if (!isValid())
        return false;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if ( ::connect(m_sockfd, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
        return false;
    return true;
}

bool TCPSocket::setNonBlocking(bool flag) const
{
    if (!isValid())
        return false;
    int opt = fcntl(m_sockfd, F_GETFL, 0);
    if (opt == -1)
        return false;
    if (flag)
        opt |= O_NONBLOCK;
    else
        opt &= ~O_NONBLOCK;
    if (fcntl(m_sockfd, F_SETFL, opt) == -1)
        return false;
    return true;
}
bool TCPSocket::reuseaddr() const
{
    if (!isValid())
        return false;

    int on = 1;
    if (setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
        return false;
    return true;
}
bool TCPSocket::close()
{
    if (!isValid())
        return false;
    ::close(m_sockfd);
    m_sockfd = -1;
    return true;
}

/** Server TCP Socket**/
TCPServer::TCPServer(unsigned short int port, const char *ip, int backlog)
throw(SocketException)
{
    if (ip != NULL)
        strcpy(m_ipv4_addr, ip);
    if (create() == false)
        throw SocketException("tcp server create error");
    if (reuseaddr() == false)
        throw SocketException("tcp server reuseaddr error");
    if (bind(port, ip) == false)
        throw SocketException("tcp server bind error");
    if (listen(backlog) == false)
        throw SocketException("tcp server listen error");
}
TCPServer::~TCPServer() {}
void TCPServer::accept(TCPClient &client) const
throw(SocketException)
{
    //显式调用基类TCPSocket的accept
    if (TCPSocket::accept(client) == -1)
        throw SocketException("tcp server accept error");
}

int TCPServer::addClient(TCPClient *client){
    //将client添加到epoll中
    struct epoll_event ep_ev = {0};
    ep_ev.data.ptr = client;
    int oper = EPOLL_CTL_ADD;
    ep_ev.events = EPOLLIN;
    if (epoll_ctl(epoll.getEpollFd(), oper, client->getfd(), &ep_ev) < 0){
        std::cout << "event add failed " << client->getfd() << std::endl;
        return -1;
    }
    return 0;
}

int TCPServer::delClient(TCPClient *client) {
    struct epoll_event event_del;
    event_del.data.fd = client->getfd();
    if( ::epoll_ctl(epoll.getEpollFd(), EPOLL_CTL_DEL, client->getfd(), &event_del) == -1 )
        throw EpollException("epoll_ctl_del error");
    for (auto it = clients.begin(); it != clients.end();it++){
        if ((*it)->getfd() == client->getfd()) {
            clients.erase(it);
            break;
        }
    }
    return 0;
}

int TCPServer::modClient(TCPClient *client) {
    struct epoll_event ev;
    bzero(&ev, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = client->getfd();
    ev.data.ptr = client;
    if( ::epoll_ctl(epoll.getEpollFd(), EPOLL_CTL_MOD, client->getfd(), &ev) == -1 )
        throw EpollException("epoll_ctl_mod error");
    return 0;
}

void TCPServer::getInfo(TCPClient* client) {
    Json::Value root;
    Json::FastWriter fast_writer;
    root["ip"] = getIpv4Addr();
    std::cout << getIpv4Addr() << std::endl;
    root["city"] = utils.getCityByIp();
    root["os"] = utils.getOS();
    //TODO:版本信息修改
    root["version"] = "v1.0";
    std::string json_str = fast_writer.write(root);
    strcpy(client->pcmd.msg, json_str.c_str());
    client->pcmd.len = strlen(client->pcmd.msg);
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.ptr = client;
    epoll_ctl(epoll.getEpollFd(), EPOLL_CTL_MOD, client->getfd(), &ev);
}

void TCPServer::startTor(TCPClient* client) {
    std::cout << "tor start..." << std::endl;
    strcpy(client->pcmd.msg, "tor start!");
    client->pcmd.len = strlen(client->pcmd.msg);
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.ptr = client;
    epoll_ctl(epoll.getEpollFd(), EPOLL_CTL_MOD, client->getfd(), &ev);
}

void TCPServer::stopTor(TCPClient* client) {

}

//获取tor流量并反馈前继节点或后继节点
void* catchTorCap(void* arg) {
    std::cout << "into catchTorCap thread..." << std::endl;
    char filter_port[] = "port ";
    char filter_middle[] = " and ip host ";
    char filter[128] = "\0";
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;

    TCPServer *server = (TCPServer *)arg;

    strcat(filter, filter_port);
    strcat(filter, server->tor_port);
    strcat(filter, filter_middle);
    strcat(filter, server->getIpv4Addr());
    std::cout << filter << std::endl;

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    //
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    }

    std::cout << "device: " << dev << std::endl;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    }

    while (1){
        pcap_loop(handle, 1, TCPServer::got_packet, reinterpret_cast<u_char *>(server));
    }
    //pcap_freealldevs(dev);
}

void TCPServer::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */
    TCPServer *server = (TCPServer *)args;

    struct ip_data *ip_d;
    struct tcp_data *tcp_d;
    struct ethernet_data *ether_d;

    u_int size_ip;
    u_int size_tcp;

    ip_d = (struct ip_data*)malloc(sizeof(struct ip_data));
    tcp_d = (struct tcp_data*)malloc(sizeof(struct tcp_data));
    ether_d = (struct ethernet_data*)malloc(sizeof(struct ethernet_data));

    ethernet = (struct sniff_ethernet*)(packet);
    for (int i = 0; i < ETHER_ADDR_LEN; i++){
        ether_d->mac_src[i] = ethernet->ether_shost[i];
        ether_d->mac_dst[i] = ethernet->ether_dhost[i];
    }

#ifdef DEBUG
    //printf("ethernet src:%x");
    //printf("ethernet dst:%x");
#endif

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    ip_d->ip_src = ip->ip_dst;
    ip_d->ip_dst = ip->ip_src;

    Json::Value root;
    Json::FastWriter fast_writer;
    std::string json_str;
    root["ip"] = server->getIpv4Addr();
    if (strcmp(server->getIpv4Addr(), inet_ntoa(ip->ip_dst)) == 0) {
        //获取ip_src(当前节点的前继节点)
        //将json信息写入到每个client的msg中
        root["ip_in"] = inet_ntoa(ip->ip_src);
        root["ip_out"] = "";
        json_str = fast_writer.write(root);
    }else if (strcmp(server->getIpv4Addr(), inet_ntoa(ip->ip_src)) == 0){
        root["ip_in"] = "";
        root["ip_out"] = inet_ntoa(ip->ip_dst);
        json_str = fast_writer.write(root);
    }
    //将每个client发送到EPOLLOUT事件中
    pthread_mutex_lock(&server->clients_mutex);
    std::vector<struct epoll_event> ev(server->clients.size());
    for (int i = 0; i < server->clients.size(); i++){
        strcpy(server->clients[i]->pcmd.msg, json_str.c_str());
        server->clients[i]->pcmd.len = strlen(server->clients[i]->pcmd.msg);
        ev[i].events = EPOLLOUT;
        ev[i].data.ptr = server->clients[i];
        epoll_ctl(server->epoll.getEpollFd(), EPOLL_CTL_MOD, server->clients[i]->getfd(), &(ev[i]));
    }
    pthread_mutex_unlock(&server->clients_mutex);
}

int TCPServer::startCatch() {
    pthread_t th;
    int ret = pthread_create(&th, NULL, catchTorCap, this);
    if (ret != 0){
        std::cout << "create thread error!" << std::endl;
        return -1;
    }
    return 0;
}

TCPClient TCPServer::accept() const
throw(SocketException)
{
    TCPClient client;
    if (TCPSocket::accept(client) == -1)
        throw SocketException("tcp server accept error");
    return client;
}

/** client TCP Socket **/
TCPClient::TCPClient(unsigned short int port, const char *ip)
throw(SocketException)
{
    if (create() == false)
        throw SocketException("tcp client create error");
    if (connect(port, ip) == false)
        throw SocketException("tcp client connect error");
}
TCPClient::TCPClient() {}
TCPClient::TCPClient(int clientfd)
{
    if (clientfd < 0)
        throw SocketException("tcp client create (parameter)error");
    m_sockfd = clientfd;
}
TCPClient::~TCPClient() {}
/** client端特有的send/receive **/
static ssize_t readn(int fd, void *buf, size_t count);
static ssize_t writen(int fd, const void *buf, size_t count);

//send
size_t TCPClient::send(const std::string& message)
const throw(SocketException)
{
    Packet buf;
    buf.msgLen = htonl(message.length());
    strcpy(buf.text, message.c_str());
    if (writen(m_sockfd, &buf, sizeof(buf.msgLen)+message.length()) == -1)
        throw SocketException("tcp client writen error");
    return message.length();
}
//receive
size_t TCPClient::receive(std::string& message)
const throw(SocketException)
{
    //首先读取头部
    Packet buf = {0, 0};
    size_t readBytes = readn(m_sockfd, &buf.msgLen, sizeof(buf.msgLen));
    if (readBytes == (size_t)-1)
        throw SocketException("tcp client readn error");
    else if (readBytes != sizeof(buf.msgLen))
        throw SocketException("peer connect closed");

    //然后读取数据部分
    unsigned int lenHost = ntohl(buf.msgLen);
    readBytes = readn(m_sockfd, buf.text, lenHost);
    if (readBytes == (size_t)-1)
        throw SocketException("tcp client readn error");
    else if (readBytes != lenHost)
        throw SocketException("peer connect closed");
    message = buf.text;
    return message.length();
}
size_t TCPClient::read(void *buf, size_t count) throw(SocketException)
{
    ssize_t readBytes = ::read(m_sockfd, buf, count);
    if (readBytes == -1)
        throw SocketException("tcp client read error");
    return (size_t)readBytes;
}
void TCPClient::write(const void *buf, size_t count) throw(SocketException)
{
    if ( ::write(m_sockfd, buf, count) == -1 )
        throw SocketException("tcp client write error");
}
size_t TCPClient::write(const char *msg) throw(SocketException)
{
    if ( ::write(m_sockfd, msg, strlen(msg)) == -1 )
        throw SocketException("tcp client write error");
    return strlen(msg);
}

/** readn/writen实现部分 **/
static ssize_t readn(int fd, void *buf, size_t count)
{
    size_t nLeft = count;
    ssize_t nRead = 0;
    char *pBuf = (char *)buf;
    while (nLeft > 0)
    {
        if ((nRead = read(fd, pBuf, nLeft)) < 0)
        {
            //如果读取操作是被信号打断了, 则说明还可以继续读
            if (errno == EINTR)
                continue;
            //否则就是其他错误
            else
                return -1;
        }
        //读取到末尾
        else if (nRead == 0)
            return count-nLeft;

        //正常读取
        nLeft -= nRead;
        pBuf += nRead;
    }
    return count;
}
static ssize_t writen(int fd, const void *buf, size_t count)
{
    size_t nLeft = count;
    ssize_t nWritten = 0;
    char *pBuf = (char *)buf;
    while (nLeft > 0)
    {
        if ((nWritten = write(fd, pBuf, nLeft)) < 0)
        {
            //如果写入操作是被信号打断了, 则说明还可以继续写入
            if (errno == EINTR)
                continue;
            //否则就是其他错误
            else
                return -1;
        }
        //如果 ==0则说明是什么也没写入, 可以继续写
        else if (nWritten == 0)
            continue;

        //正常写入
        nLeft -= nWritten;
        pBuf += nWritten;
    }
    return count;
}
