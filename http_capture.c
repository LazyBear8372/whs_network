#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  // Step 0: check weather the packet is TCP
  struct ethheader *eth = (struct ethheader *)packet;
  struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader)); 
  struct tcpheader* tcp = (struct tcpheader*) (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
                          
  if (ip->iph_protocol != IPPROTO_TCP || !(ntohs(tcp->tcp_sport) == 80 || ntohs(tcp->tcp_dport) == 80)) {
    return;
  }
  
  // Step 1: check Ethernet header
  printf("       src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  
  printf("       dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  
  // Step 2: check IP header
  printf("        src IP: %s\n", inet_ntoa(ip->iph_sourceip));   
  printf("        dst IP: %s\n", inet_ntoa(ip->iph_destip));    

  // Step 3: check TCP header
  printf("      src Port: %hu\n", ntohs(tcp->tcp_sport));
  printf("      dst Port: %hu\n", ntohs(tcp->tcp_dport));
  
  // Step 4: check HTTP Message
  int payload_len = header->caplen - (sizeof(struct ethheader) + ip->iph_ihl*4 + TH_OFF(tcp)*4);

  u_char* http = (u_char*) (packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + TH_OFF(tcp) * 4);
  
  printf("  HTTP Message: ");
  if (payload_len > 0) {
    for (int i = 0; i < payload_len; i++) {
      
      // 출력 가능한 문자만 그대로, 나머지(바이너리)는 '.'으로
      if (isprint(http[i]) || http[i] == '\n' || http[i] == '\r')
        printf("%c", http[i]);
      else
        printf(".");
    }
  }
  printf("\n");
  
  return;
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 net;
  char* interface = "wlp2s0";

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

  // Step 2: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  
  return 0;
}
