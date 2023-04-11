#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netdb.h>
#include "client.h"

#define BUFFLEN (4 * 1024)
#define MTU 1400
#define BIND_HOST "0.0.0.0"
#define TUN_DEV_NAME "tun0"

client* cli = new client();

int create_device(int* fd)
{
  struct ifreq ifr;
  int fd_temp, err;
  char *clonedev = "/dev/net/tun";

  if( (fd_temp = open(clonedev , O_RDWR)) < 0 ) {
      perror("Opening /dev/net/tun");
  return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

	// Flag for creating tun interface, without the 4 prefix bytes on each message
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
	// Name the tun device
	strncpy(ifr.ifr_name, TUN_DEV_NAME, IF_NAMESIZE);

	// Crete the interface using ioctl call
	if( (err = ioctl(fd_temp, TUNSETIFF, (void *)&ifr)) < 0 ) {
        perror("Error: ioctl(TUNSETIFF)");
        close(fd_temp);
        return err;
    }
    
  // PERSISTENT INTERFACE
  // if( (err = ioctl(fd_temp, TUNSETPERSIST, 1)) < 0 ) {
  //     perror("Error: ioctl(TUNSETPERSIST)");
  //     close(fd_temp);
  //     return err;
  // }
	*fd = fd_temp;
	return 0;
}

static void run(char *cmd) {
  printf("Execute `%s`\n", cmd);
  if (system(cmd)) {
    perror(cmd);
    exit(1);
  }
}

/*
 * Configure IP address and MTU of VPN interface /dev/tun0
 */
void ifconfig() {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ifconfig %s 10.8.0.2/16 mtu %d up", TUN_DEV_NAME, MTU);
  //snprintf(cmd, sizeof(cmd), "ifconfig tun0 10.8.0.1/16 mtu %d up", MTU);
  run(cmd);
}

/*
 * Setup route table via `iptables` & `ip route`
 */
void setup_route_table() {
  char cmd[1024];
  run("sysctl -w net.ipv4.ip_forward=1");
  snprintf(cmd, sizeof(cmd), "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", TUN_DEV_NAME);
  run(cmd);
  snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT", TUN_DEV_NAME);
  run(cmd);
  snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -o %s -j ACCEPT", TUN_DEV_NAME);
  run(cmd);
  snprintf(cmd, sizeof(cmd), "ip route add %s via $(ip route show 0/0 | awk '/default/ {print $3}')", EXTERNAL_SERVER_IP);
  run(cmd);
  snprintf(cmd, sizeof(cmd), "ip route add 0/1 dev %s", TUN_DEV_NAME);
  run(cmd);
  snprintf(cmd, sizeof(cmd), "ip route add 128/1 dev %s", TUN_DEV_NAME);
  run(cmd);

  // CLIENT ?
  // run("iptables -t nat -A POSTROUTING -s 10.8.0.0/16 ! -d 10.8.0.0/16 -m comment --comment 'vpndemo' -j MASQUERADE");
  // run("iptables -A FORWARD -s 10.8.0.0/16 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  // run("iptables -A FORWARD -d 10.8.0.0/16 -j ACCEPT");
}


int main(int argc, char* argv[]) 
{
	int tun_fd = 0;
  char* dev_name = nullptr;
  int socket_fd = 0;
  int client_socket = 0;

  if (create_device(&tun_fd) < 0)
  {
      perror("create_device error");
      return -1;
  }
  ifconfig();
  setup_route_table();
    
  int error = cli->createConnection();
  if (error != 0)
  {
      printf("Client failed to connect\n");
      exit(EXIT_FAILURE);
  }

  printf("Device connected press any key to continue\n");
  getchar();

  char buffer[BUFFLEN];
  while (1) {
        printf("Reading from tun interface...\n");
        // Read an IP packet from self
        ssize_t count = read(tun_fd, buffer, BUFFLEN);
        if (count < 0)
        {
            perror("Failed to read from a socket");
            return -1;
        }
        printf("Read %d bytes\n", count);


        // Send request to the pi
        int bytesSNDExt = sendto(cli->getSocket(), buffer, count, 0, (struct sockaddr *) &cli->from, cli->from_size);
        if (bytesSNDExt < 0){
            printf("Failed to send msg Error: %s\n", strerror(errno));
            close(cli->getSocket());
            exit(1);
        }
        printf("Msg sent to the pi %d bytes\n", bytesSNDExt);

        // // Get the response from the pi
        //  size_t msg_size = 512 * sizeof(char);
        // char* msgG = (char*) malloc(msg_size);
        // int bytesRCVExt = recvfrom(cli->getSocket(), msgG, msg_size, 0, (struct sockaddr *) &cli->from, &cli->from_size);
        // if (bytesRCVExt < 0){
        //     printf("Failed to recv msg Error: %s\n", strerror(errno));
        //     close(cli->getSocket());
        //     free(msgG);
        //     exit(1);
        // }
        // char* ip_host1 = (char*) malloc(15);
        // inet_ntop(AF_INET, &(cli->from.sin_addr), ip_host1,15);
        // printf("Message from: %s, size: %d\n", ip_host1, bytesRCVExt);

        // // Close connection to the pi
        // close(cli->getSocket());

        // dnsMsg msgRet = dnsMsg();
        // msgRet.processHeader(msgG);
        // msgRet.printHeader();
        // msgRet.processQuestion(msgG);
        
    }

    return 0;
}
