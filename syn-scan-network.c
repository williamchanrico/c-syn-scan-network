/*
* Title: Syn Scan Network
* Description: Scan if a port if open by sending SYN packet(s) to all IP(s) in a network
* Date: 24-Apr-2018
* Author: William Chanrico
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <math.h>

#define MAXLINE 4096

int parse_cidr(const char *, struct in_addr *, struct in_addr *);
void err_exit(char *, ...);
void *receive_ack(void *);
void process_packet(unsigned char *, int, char *);
void get_local_ip(char *);
void ip_to_host(const char *, char *);
char *hostname_to_ip(char *);
const char *dotted_quad(const struct in_addr *);
unsigned short check_sum(unsigned short *, int);
void str2int(int *out, char *s, int base);
 
struct pseudo_header{    //Needed for checksum calculation
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;
   
  struct tcphdr tcp;
};
 
double program_duration;
struct timespec start_time, finish_time;
unsigned int total_open_host = 0;
struct in_addr dest_ip;
int source_port = 46156;
char source_ip[20];

int main(int argc, char *argv[]){
  clock_gettime(CLOCK_MONOTONIC, &start_time);

  if(argc != 3){
    printf("usage: %s <IP/CIDR> <Port1,Port2,...>\n", argv[0]);
    printf("example:\n");
    printf("\t%s 166.104.0.0/16 80,443,8080\n", argv[0]);
    printf("\t%s 35.186.153.3 80,443,8080\n", argv[0]);
    printf("\t%s 166.104.177.24 80\n", argv[0]);

    return 1;
  }

  int64_t num_hosts;
  struct in_addr addr, mask, wildcard, network, broadcast, min, max;
  
  char *port_list = malloc(strlen(argv[2]) + 1);
  strcpy(port_list, argv[2]);

  int bits = parse_cidr(argv[1], &addr, &mask);
  if (bits == -1)
    err_exit("Invalid network address: %s\nValid example: 166.104.0.0/16\n", argv[1]);
  
  get_local_ip(source_ip);

  wildcard = mask;
  wildcard.s_addr = ~wildcard.s_addr;

  network = addr;
  network.s_addr &= mask.s_addr;

  broadcast = addr;
  broadcast.s_addr |= wildcard.s_addr;

  min = network;
  max = broadcast;

  if(network.s_addr != broadcast.s_addr){
    min.s_addr = htonl(ntohl(min.s_addr) + 1);
    max.s_addr = htonl(ntohl(max.s_addr) - 1);
  }
  
  num_hosts = (int64_t) ntohl(broadcast.s_addr) - ntohl(network.s_addr) + 1;
  printf("SYN scan IP range for port(s) [%s]\n", argv[2]);
  printf("From    : %s\n", dotted_quad(&min));
  printf("To      : %s\n",  dotted_quad(&max));
  printf("%" PRId64 " host(s)\n\n", num_hosts);
  fflush(stdout);

  int host_count;
  for(host_count = 0; host_count < num_hosts; host_count++){
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sockfd < 0)
      err_exit("Error creating socket. Error number: %d. Error message: %s\n", errno, strerror(errno));

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
      err_exit("Error setting IP_HDRINCL. Error number: %d. Error message: %s\n", errno, strerror(errno));

    char datagram[4096];    
   
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
     
    struct sockaddr_in dest;
    struct pseudo_header psh;
     
    const char *target = dotted_quad(&min);

    if(inet_addr(target) == -1)
      err_exit("Invalid address\n");

    dest_ip.s_addr = inet_addr(target);

    memset(datagram, 0, 4096);
     
    //Fill in the IP Header
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id       = htons(46156); //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check    = 0;      //Set to 0 before calculating checksum
    iph->saddr    = inet_addr(source_ip);    //Spoof the source ip address
    iph->daddr    = dest_ip.s_addr;
    iph->check    = check_sum( (unsigned short *) datagram, iph->tot_len >> 1);
     
    //TCP Header
    tcph->source  = htons(source_port);
    tcph->dest    = htons(80);
    tcph->seq     = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff    = sizeof(struct tcphdr) / 4;      //Size of tcp header
    tcph->fin     = 0;
    tcph->syn     = 1;
    tcph->rst     = 0;
    tcph->psh     = 0;
    tcph->ack     = 0;
    tcph->urg     = 0;
    tcph->window  = htons(14600);  //Maximum allowed window size
    tcph->check   = 0; //If you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;
        
    pthread_t sniffer_thread;
 
    if(pthread_create(&sniffer_thread, NULL, receive_ack, NULL) < 0)
      err_exit("Could not create sniffer thread. Error number: %d. Error message: %s\n", errno, strerror(errno));
    
    strcpy(port_list, argv[2]);
    char *pch = strtok(port_list, ",");
    while(pch != NULL){  
      dest.sin_family = AF_INET;
      dest.sin_addr.s_addr = dest_ip.s_addr;

      int port;
      str2int(&port, pch, 10);
      tcph->dest = htons(port);
      tcph->check = 0; //If you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
       
      psh.source_address  = inet_addr(source_ip);
      psh.dest_address    = dest.sin_addr.s_addr;
      psh.placeholder     = 0;
      psh.protocol        = IPPROTO_TCP;
      psh.tcp_length      = htons(sizeof(struct tcphdr));
       
      memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
       
      tcph->check = check_sum( (unsigned short*) &psh, sizeof(struct pseudo_header));

      // printf("[DEBUG] Sending SYN packet to %s:%d\n", target, port);
      // fflush(stdout);
      if (sendto(sockfd, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(dest)) < 0)
        err_exit("Error sending syn packet. Error number: %d. Error message: %s\n", errno, strerror(errno));
      
      pch = strtok(NULL, ",");
    }

    close(sockfd);

    /* Create sniffer_thread for every ports if you want to account all TCP SYN in a host */
    pthread_join(sniffer_thread, NULL); //This will only make 1 sniffer to receive 1 reply from any port
    
    min.s_addr = htonl(ntohl(min.s_addr) + 1);
  }

  clock_gettime(CLOCK_MONOTONIC, &finish_time);
  program_duration = (finish_time.tv_sec - start_time.tv_sec);
  program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

  int hours_duration = program_duration / 3600;
  int mins_duration = (int) (program_duration / 60) % 60;
  double secs_duration = fmod(program_duration, 60);

  printf("\nTotal active host: %d\n", total_open_host);
  printf("Scan duration    : %d hour(s) %d min(s) %.05lf sec(s)\n", hours_duration, mins_duration, secs_duration);
  
  return 0;
}


/**
  Convert string s to integer
 */
void str2int(int *out, char *s, int base){
    if (s[0] == '\0' || isspace((unsigned char) s[0]))
        return;
      
    char *end;
    errno = 0;
    long l = strtol(s, &end, base);

    if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
        return;
    if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN))
        return;
    if (*end != '\0')
        return;

    *out = l;
    
    return;
}

/**
  Parses a string in CIDR notation as an IPv4 address and netmask.
  Returns the number of bits in the netmask if the string is valid.
  Returns -1 if the string is invalid.
 */
int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask) {
  int bits = inet_net_pton(AF_INET, cidr, addr, sizeof addr);

  mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
  return bits; 
}   

/**
  Formats the IPv4 address in dotted quad notation, using a static buffer.
 */
const char *dotted_quad(const struct in_addr *addr) {
  static char buf[INET_ADDRSTRLEN];
  
  return inet_ntop(AF_INET, addr, buf, sizeof buf);
}   

/**
  Exit the program with EXIT_FAILURE code
 */
void err_exit(char *fmt, ...){
  va_list ap;
  char buff[MAXLINE];

  va_start(ap, fmt);
  vsprintf(buff, fmt, ap);

  fflush(stdout);
  fputs(buff, stderr);
  fflush(stderr);

  exit(EXIT_FAILURE);
}

/**
  Method to sniff incoming packets and look for Ack replies  
*/ 
int start_sniffer(){
  int sock_raw;
   
  socklen_t saddr_size, data_size;
  struct sockaddr_in saddr;
   
  unsigned char *buffer = (unsigned char *) malloc(65536);
   
  //Create a raw socket that shall sniff
  sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(sock_raw < 0){
    printf("Socket Error\n");
    fflush(stdout);
    return 1;
  }
   
  saddr_size = sizeof(saddr);

  //Receive a packet
  data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr *) &saddr, &saddr_size);

  if(data_size < 0){
    printf("Recvfrom error, failed to get packets\n");
    fflush(stdout);
    return 1;
  }
   
  process_packet(buffer, data_size, inet_ntoa(saddr.sin_addr));
  close(sock_raw);

  return 0;
}

/**
  Method to sniff incoming packets and look for Ack replies  
*/
void *receive_ack(void *ptr){
  start_sniffer();

  return NULL;
}
 
/**
  Method to process incoming packets and look for Ack replies  
*/
void process_packet(unsigned char *buffer, int size, char *source_ip){
  //Get the IP Header part of this packet
  struct iphdr *iph = (struct iphdr*) buffer;
  struct sockaddr_in source, dest;
  unsigned short iphdrlen;
   
  if(iph->protocol == 6){
    struct iphdr *iph = (struct iphdr *) buffer;
    iphdrlen = iph->ihl * 4;
 
    struct tcphdr *tcph = (struct tcphdr*) (buffer + iphdrlen);
         
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
 
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr){
      char source_host[NI_MAXHOST];
      ip_to_host(source_ip, source_host);

      // printf("Port %d open\n", ntohs(tcph->source));
      printf("%s\t%s\n", source_ip, source_host);
      fflush(stdout);
      
      ++total_open_host;
    }
  }
}
 
/**
 Checksums - IP and TCP
 */
unsigned short check_sum(unsigned short *ptr, int nbytes){
  register long sum;
  register short answer;
  unsigned short oddbyte;

  sum = 0;
  while(nbytes>1){
    sum += *ptr++;
    nbytes -= 2;
  }

  if(nbytes == 1) {
    oddbyte = 0;
    *( (u_char*) &oddbyte) = *(u_char*) ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short) ~sum;
   
  return answer;
}
 
/**
  Get ip from domain name
 */
char *hostname_to_ip(char *hostname){
  struct hostent *he;
  struct in_addr **addr_list;
       
  if( (he = gethostbyname(hostname)) == NULL)
    err_exit("gethostbyname");

  addr_list = (struct in_addr **) he->h_addr_list;
   
  int a;
  for(a = 0; addr_list[a] != NULL; a++)
    return inet_ntoa(*addr_list[a]);  //Return the first one;

  return NULL;
}
 
/**
 Get source IP of the system running this program
 */
void get_local_ip(char *buffer){
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  const char *kGoogleDnsIp = "8.8.8.8";
  int dns_port = 53;

  struct sockaddr_in serv;

  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
  serv.sin_port = htons(dns_port);

  if(connect(sock, (const struct sockaddr*) &serv, sizeof(serv)) != 0)
    err_exit("Failed to get local IP\n");

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  
  if(getsockname(sock, (struct sockaddr*) &name, &namelen) != 0)
    err_exit("Failed to get local IP");

  inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

  close(sock);
}

/**
 Get hostname of an IP address
 */
void ip_to_host(const char *ip, char *buffer){
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port        = 0;

    if(getnameinfo( (struct sockaddr *) &dest, sizeof(dest), buffer, NI_MAXHOST, NULL, 0, NI_NAMEREQD) != 0)
      strcpy(buffer, "Hostname can't be determined");
}