//
// Created by Dominika Bobik on 2/6/23.
//

#include <netinet/in.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <arpa/inet.h>

#ifndef DNSTEST_CLIENT_H
#define DNSTEST_CLIENT_H

#define EXTERNAL_SERVER_IP "192.168.0.171"
#define PORT 55555

using namespace std;

class client {
    private:
        int socket_fd;
    public:
        struct sockaddr_in from{};
        socklen_t from_size;
        client();
        int createConnection();
        int getSocket();
};

#endif //DNSTEST_CLIENT_H

