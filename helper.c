#include "helper.h"
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h>     //Provides declarations for ip header

#define UDP_HEADER_SIZE 8

int has_fin_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_FIN )
        return 1;
    else
        return 0;
}

int has_syn_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_SYN )
        return 1;
    else
        return 0;
}

int has_rst_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_RST )
        return 1;
    else
        return 0;
}

int has_push_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_PUSH )
        return 1;
    else
        return 0;
}

int has_ack_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_ACK )
        return 1;
    else
        return 0;
}

int has_urg_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_URG )
        return 1;
    else
        return 0;
}

/*
int has_ece_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_ECE )
        return 1;
    else
        return 0;
}

int has_cwr_flag(const u_char *buffer){
    struct iphdr *iph = (struct iphdr*)(buffer);
    struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
    if(tcpheader->th_flags & TH_CWR )
        return 1;
    else
        return 0;
}
*/


int get_payload_len(const u_char *buffer, uint32_t proto)
{
    struct iphdr *iph = (struct iphdr*)(buffer);
    if (proto==6)
    {
        struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
        int tcpdatalen = ntohs(iph->tot_len) - (tcpheader->doff * 4) - (iph->ihl * 4);
        return tcpdatalen;
    }
    else if(proto==17)
    {
        struct udphdr * udpheader = (struct udphdr*)(buffer + iph->ihl * 4);
        int udpdatalen = ntohs(iph->tot_len) - UDP_HEADER_SIZE- (iph->ihl * 4);
        return udpdatalen;
    }
}

int get_header_len(const u_char *buffer, uint32_t proto)
{
    struct iphdr *iph = (struct iphdr*)(buffer);
    if (proto==6)
    {
        struct tcphdr *tcpheader = (struct tcphdr*)(buffer + iph->ihl*4);
        return tcpheader->doff*4;
    }
    else if(proto==17)
    {
		//size of the UDP header is 8
		// ref https://www.winpcap.org/pipermail/winpcap-users/2007-September/002104.html
		return 8;
        struct udphdr * udpheader = (struct udphdr*)(buffer + iph->ihl * 4);
        int udpdatalen = ntohs(iph->tot_len) - (iph->ihl * 4);
        return udpdatalen;
    }
}


double max(double a, double b)
{
    if(a>=b) return a;
    else return b;
}

double min(double a, double b)
{
    if(a<=b) return a;
    else return b;
}

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{  
  // preserve *y
  struct timeval yy = *y;
  y = &yy;

  /* Perform the carry for the later subtraction by updating y. */  
  if (x->tv_usec < y->tv_usec) {  
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;  
    y->tv_usec -= 1000000 * nsec;  
    y->tv_sec += nsec;  
  }  
  if (x->tv_usec - y->tv_usec > 1000000) {  
    int nsec = (y->tv_usec - x->tv_usec) / 1000000;  
    y->tv_usec += 1000000 * nsec;  
    y->tv_sec -= nsec;  
  }  

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */  
  result->tv_sec = x->tv_sec - y->tv_sec;  
  result->tv_usec = x->tv_usec - y->tv_usec;  

  /* Return 1 if result is negative. */  
  return x->tv_sec < y->tv_sec;  
}

struct timeval get_max(struct timeval a, struct timeval b)
{

    long a_ms = a.tv_sec*MCS_IN_SEC + a.tv_usec;
    long b_ms = b.tv_sec*MCS_IN_SEC + b.tv_usec;
    if(a_ms>b_ms)
        return a;
    else
        return b;
}

