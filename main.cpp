#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <regex.h>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

Mac MyMac;
Ip MyIp;

struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

void usage()
{
  printf("syntax : tcp-block <interface> <pattern>\n");
  printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void GetMyAddr(const char *interface)
{
  int sock;
  struct ifreq ifr;
  
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock == -1)
  {
    perror("socket");
    printf("Cannot Create Socket.\n");
    exit(-1);
  }

  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

  // MAC
  if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1)
  {
    perror("ioctl");
    close(sock);
    printf("Cannot Get My Mac Address");
    exit(-1);
  }

  unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  MyMac = Mac(mac);

  if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
  {
    perror("ioctl");
    close(sock);
    printf("Cannot Get My Ip Address");
    exit(-1);
  }

  close(sock);

  // Ip
  struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
  MyIp = Ip(inet_ntoa(ipaddr->sin_addr));

  return;
}

uint16_t get_checksum(uint16_t *ptr, int len)
{
  uint32_t sum = 0;
  uint16_t odd = 0;

  while (len > 1)
  {
    sum += *ptr++;
    len -= 2;
  }

  if (len == 1)
  {
    *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
    sum += odd;
  }

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return (uint16_t)~sum;
}

int main(int argc, char *argv[])
{
  if (argc != 3)
  {
    usage();
    return 0;
  }

  const char *interface = argv[1];
  const char *pattern = argv[2];

  GetMyAddr(interface); // get My Mac & Ip

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
  if (handle == nullptr)
  {
    fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
    return -1;
  }

  struct pcap_pkthdr *header;
  const u_char *packet;
  int res;

  while (1)
  {
    res = pcap_next_ex(handle, &header, &packet);
    if (res == 0)
    {
      continue;
    }
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
      break;
    }

    EthHdr *eth_hdr = (EthHdr *)packet;
    if (eth_hdr->type() == EthHdr::Ip4)
    {
      IpHdr *ip_hdr = (IpHdr *)(packet + sizeof(*eth_hdr));
      uint32_t ip_pkt_size = ntohs(ip_hdr->total_len);
      uint16_t ip_hdr_size = ip_hdr->ip_len * 4;

      if (ip_hdr->proto == 6)
      { // tcp
        TcpHdr *tcp_hdr = (TcpHdr *)(packet + sizeof(*eth_hdr) + sizeof(*ip_hdr));
        uint32_t tcp_hdr_size = tcp_hdr->th_off * 4;
        uint32_t data_size = ip_pkt_size - ip_hdr_size - tcp_hdr_size;

        if (data_size <= 0)
        {
          continue;
        }

        char *data = (char *)((char *)tcp_hdr + tcp_hdr_size);

        if (strstr(data, pattern) && !strncmp(data, "GET", 3))
        {
          // pattern found !!
          // Backward Fin Packet
          printf("Pattern Found!!\n");

          int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
          if (sock == -1)
          {
            printf("Failed to create socket.\n");
            return 1;
          }

          const char *tcp_data = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
          uint32_t total_size = sizeof(IpHdr) + sizeof(TcpHdr) + strlen(tcp_data);

          char *backward_packet = (char *)malloc(total_size + 1);
          memset(backward_packet, 0, total_size + 1);

          IpHdr *backward_ip_hdr = (IpHdr *)backward_packet;
          TcpHdr *backward_tcp_hdr = (TcpHdr *)(backward_packet + sizeof(IpHdr));
          memcpy(backward_packet + sizeof(IpHdr) + sizeof(TcpHdr), tcp_data, strlen(tcp_data));

          backward_ip_hdr->ip_len = sizeof(IpHdr) / 4;
          backward_ip_hdr->ip_v = 4;
          backward_ip_hdr->total_len = htons(total_size);
          backward_ip_hdr->ttl = 128;
          backward_ip_hdr->proto = 6;
          backward_ip_hdr->sip_ = ip_hdr->dip_;
          backward_ip_hdr->dip_ = ip_hdr->sip_;

          backward_tcp_hdr->sport = tcp_hdr->dport;
          backward_tcp_hdr->dport = tcp_hdr->sport;
          backward_tcp_hdr->seqnum = tcp_hdr->acknum;
          backward_tcp_hdr->acknum = htonl(ntohl(tcp_hdr->seqnum) + data_size);
          backward_tcp_hdr->th_off = tcp_hdr_size / 4;
          backward_tcp_hdr->flags = 0b00010001;
          backward_tcp_hdr->win = htons(60000);

          pseudo_header *psh;
          psh->source_address = ip_hdr->dip_;
          psh->dest_address = ip_hdr->sip_;
          psh->placeholder = 0;
          psh->protocol = IPPROTO_TCP;
          psh->tcp_length = htons(tcp_hdr_size + data_size);

          uint32_t checksum = get_checksum((uint16_t *)tcp_hdr, sizeof(TcpHdr)) + get_checksum((uint16_t *)psh, sizeof(pseudo_header));
          tcp_hdr->check = (checksum & 0xffff) + (checksum >> 16);
          ip_hdr->check = get_checksum((uint16_t *)ip_hdr, ip_hdr_size);

          struct sockaddr_in rawaddr;
          rawaddr.sin_family = AF_INET;
          rawaddr.sin_port = tcp_hdr->sport;
          rawaddr.sin_addr.s_addr = ip_hdr->sip_;

          if (sendto(sock, backward_packet, total_size, 0, (struct sockaddr *)&rawaddr, sizeof(rawaddr)) < 0)
          {
            perror("Sending packet failed");
            printf("DDD");
            return -1;
          }
          
          for (int idx = 0; idx < total_size + 1; idx ++) {
          
          	printf("%c", backward_packet[idx]);
          }
          printf("\n");

          free(backward_packet);
          close(sock);

          //////////forward packet//////////
          total_size = sizeof(EthHdr) + ip_hdr_size + sizeof(TcpHdr);
          char *forward_packet = (char *)malloc(total_size + 1);
          memset(forward_packet, 0, total_size + 1);
          memcpy(forward_packet, packet, total_size);

          eth_hdr = (EthHdr *)forward_packet;
          ip_hdr = (IpHdr *)(forward_packet + sizeof(EthHdr));
          tcp_hdr = (TcpHdr *)(forward_packet + sizeof(EthHdr) + ip_hdr_size);

          eth_hdr->smac_ = MyMac;
          ip_hdr->total_len = htons(ip_hdr_size + sizeof(TcpHdr));
          ip_hdr->check = 0;
          
          tcp_hdr->th_off = sizeof(TcpHdr) / 4;
          tcp_hdr->seqnum = htonl(ntohl(tcp_hdr->seqnum) + data_size);
          tcp_hdr->flags = 0b00010100; // RST | ACK 
          tcp_hdr->check = 0;

          psh->source_address = ip_hdr->sip_;
          psh->dest_address = ip_hdr->dip_;
          psh->protocol = IPPROTO_TCP;
          psh->tcp_length = htons(sizeof(TcpHdr));

          checksum = get_checksum((uint16_t *)tcp_hdr, sizeof(TcpHdr)) + get_checksum((uint16_t *)psh, sizeof(pseudo_header));
          tcp_hdr->check = (checksum & 0xffff) + (checksum >> 16);
          ip_hdr->check = get_checksum((uint16_t *)ip_hdr, ip_hdr_size);

          if (pcap_sendpacket(handle, reinterpret_cast<const u_char *>(forward_packet), total_size))
          {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
          }

          free(forward_packet);
        }
      }
    }
  }
  pcap_close(handle);
  return 0;
}
