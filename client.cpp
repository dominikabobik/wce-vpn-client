//
// Created by Dominika Bobik on 2/6/23.
//

#include "client.h"

client::client()
{
    socket_fd = 0;
    from_size = sizeof(from);
    bzero((char *) &from, from_size);
}

int client::createConnection()
{
    int error = 0;
    // Create socket: IPv4 domain, UDP, default protocol
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1)
    {
        printf("Error while creating socket (%d) %s \n", errno, strerror(errno));
        error = socket_fd;
        return error;
    }

    from.sin_family = AF_INET;
    from.sin_port = htons(PORT);
    from.sin_addr.s_addr = inet_addr(EXTERNAL_SERVER_IP);

    printf(" Client running                         \n");
    printf(" Port:           %d (network byte order)\n", from.sin_port);
    printf("                 %d (hostorder)         \n", PORT);
    printf(" Server address: %s                     \n", EXTERNAL_SERVER_IP);
    printf(" Domain:         AF_INET                \n");
    printf(" Protocol:       UDP                    \n\n");

    return error;
}

int client::getSocket() {
    return socket_fd;
}
