#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>			//ifreq
#include <unistd.h>
#include <string.h>			//strlen
#include <sys/socket.h>		//socket
#include <netinet/if_ether.h>	/* includes net/ethernet.h */
#include <time.h>
#include "pcap.h"
#include <pthread.h>		// gcc  test.c -o test -lpthread
#include <math.h>

#include <sys/socket.h>
#include <arpa/inet.h>			// for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>		//Provides declarations for udp header
#include <netinet/tcp.h>		//Provides declarations for tcp header
#include <netinet/ip.h>			//Provides declarations for ip header
#include <netinet/in.h>
#include "collector.h"

#define virtual_vector_size 8
//#define linearCounter_array_size 27500	// n MB * 1024(for KB) * 1024(for MB) / 4 (int size) //
//#define linearCounter_array_size 192500 //above mem used by Daehong for 100K flows, I have 700K flows
#define linearCounter_array_size 20000 //should be enought to keep active flow withing FLOWTIMEOUT
#define LIVE_INPUT 0
#define FILE_INPUT 1

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int SAMPLING_RATE;
int est;
long sampled_pkt_cnt=0;
struct tcphdr *tcpheader;
struct udphdr *udpheader;
int protocol_set[1000] = {0};

flowid_t get_flowid(const u_char *buffer)
{
    flowid_t flowid = {0}; //we shoudl return flowid after fetching from packet hdr

    struct iphdr *iph = (struct iphdr*)(buffer);
    uint32_t is,id,proto,sp,dp;
    is=iph->saddr;
    id=iph->daddr;
    proto = iph->protocol;
    protocol_set[proto]+=1;
    //printf("Proto: %d\n",proto);    
    if(proto == 1)
    {
        sp = 0;
        dp = 0;
    }else if(proto == 17)
    {  
    	udpheader = (struct udphdr*)(buffer + iph->ihl * 4);
    	sp =ntohs(udpheader->source);
        dp = ntohs(udpheader->dest);

    }else if(proto==6)//tcp or could be 0(ipv6) protocol
    {  
    	tcpheader = (struct tcphdr*)(buffer + iph->ihl * 4);
    	sp =ntohs(tcpheader->source);
        dp = ntohs(tcpheader->dest);
    }
    else{ // we wont work with these cases
        return flowid;
    }

    flowid = (flowid_t){.is=is,.id=id,.proto=proto,.sp=sp,.dp=dp};
    return flowid;
}


char outputfilename[200]; 
void write_header(char* filename);
int fwd_cnt=0;
int bwd_cnt = 0;
Collector featureCollector;
int max_num_concurrent_flows=0;

int main(int argc, char** argv)
{       
    if(argc <4)
    {
        printf("program expects 3 arguments\n 1)Pcap file \t 2) csv output file \t 3) SR"); 
        return 0;
    }
    
    char tracefile[200];
    strcpy(tracefile,argv[1]);
    strcpy(outputfilename,argv[2]);
    if (sscanf (argv[3], "%i", &SAMPLING_RATE) != 1) {
            fprintf(stderr, "error - not an integer");
    }


    est = (rand() % (2 * SAMPLING_RATE - 1)) + 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *fp;
    struct pcap_pkthdr *header;

    if ((fp = pcap_open_offline(tracefile, errbuf))==NULL)
	    fprintf(stderr, "\nUnable to open the file %s.\n", tracefile);		
    else
        printf("PCAP file opened for read successfully\n");  
    
    double total_time;
    time_t start, end;
    time(&start);
    printf("entering pcap_loop\n");
    pcap_loop(fp, 0, packet_handler, NULL);
    printf("Exiting pcap_loop\n");
    time(&end);
    total_time = ((double) (end - start)) ;
    printf("Processing Finished in %f sec\n",total_time);
     
    featureCollector.print_flow_features(outputfilename);
    featureCollector.print_sampled_packet_count(outputfilename,sampled_pkt_cnt);
    if (SAMPLING_RATE==1)//means whole data
    {
        featureCollector.print_num_concurrent_flows(outputfilename,max_num_concurrent_flows);// will be used by sgs, sketchflow and ffs for fair comparision by setting same memory for LC
    }
    //printf("Max num of flows %d\n",max_num_concurrent_flows);
    return 0;
}


int cnt=0;
int n;
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *buffer)
{
    //fixing buffer offset
    buffer = buffer + 14;
    //Careful about the above line

    flowid_t flowid =  get_flowid(buffer);

    if(flowid.proto!=6 && flowid.proto!=17) {return;}
    //printf("%"PRIu32"\n",flowid.proto);    
    cnt++;
    if(cnt==est)
    {
        cnt = 0;
        featureCollector.ht_insert_est(flowid, est,buffer,header->ts);
        n = featureCollector.get_num_concurrent_flows();
        max_num_concurrent_flows = max(n,max_num_concurrent_flows);

        est = (rand()%(2*SAMPLING_RATE - 1))+1;
        sampled_pkt_cnt++;
    }

}



