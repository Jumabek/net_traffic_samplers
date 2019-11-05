#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h> // strlen
#include <unistd.h>
#include <time.h>
#include <math.h>

#include <sys/ioctl.h>
#include <net/if.h>			//ifreq
#include <sys/socket.h>		//socket
#include <arpa/inet.h>		//inet_addr
#include <netinet/if_ether.h>	/* includes net/ethernet.h */
#include "pcap.h"
#include <pthread.h>		// gcc  test.c -o test -lpthread
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <netinet/udp.h>		//Provides declarations for udp header
#include <netinet/tcp.h>		//Provides declarations for tcp header
#include <netinet/ip.h>			//Provides declarations for ip header
#include <netinet/in.h>

#include "collector.h"

//#define linearCounter_array_size 27500	// n MB * 1024(for KB) * 1024(for MB) / 4 (int size) //
//define linearCounter_array_size 192500 //above memory is used by Daehong for 100K concurrent flows, I have 4M flows
#define LIVE_INPUT 0
#define FILE_INPUT 1

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


#define FILE_MINUTE 1
long sampled_pkt_cnt = 0;
int *ffs_counter;
int linearCounter_array_size;
struct tcphdr *tcpheader;
struct udphdr *udpheader;
int protocol_set[1000] = {0};

//declaterd in hash_t.h
/*
typedef struct flowid {
    uint32_t is;
    uint32_t id;
    uint32_t proto;
    uint32_t sp;
    uint32_t dp;
} flowid_t;
*/

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


int num_concurrent_flows;
char outputfilename[200]; 
int SAMPLING_RATE;
int param_s;
int param_l;
float est;
Collector fc;
int main(int argc, char** argv)
{       
    if(argc <6)
    {
        printf("program expects arguments\n 1)Pcap file \t \
2) csv output file \t 3)s \t 4) l parameters \t 5) sampling prob (e.g. 0.01)\n");
        printf("but argc = %d\n",argc);
        return 0;
    }
    
    char tracefile[200];
    strcpy(tracefile,argv[1]);
    strcpy(outputfilename,argv[2]);
    if (sscanf (argv[3],"%d",&param_s) !=1)
    {
        fprintf(stderr,"Error - not an integer");
    }
    if (sscanf (argv[4],"%d",&param_l) !=1)
    {
        fprintf(stderr,"Error - not an integer");
    }
    if (sscanf (argv[5],"%d",&SAMPLING_RATE) !=1)
    {
        fprintf(stderr,"Error - not an integer");
    }
    if (sscanf (argv[6],"%d",&num_concurrent_flows) !=1)
    {
        fprintf(stderr,"Error - not an integer");
    }
    
    linearCounter_array_size = num_concurrent_flows/4;
    ffs_counter = (int*) calloc(linearCounter_array_size,sizeof(int)); // div by 4 is important. 
    est = (rand()%(2*SAMPLING_RATE-1))+1;
    
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
    pcap_loop(fp, 0, packet_handler, NULL);
    time(&end);
    total_time = ((double) (end - start)) ;
    printf("Processing Finished in %f sec\n",total_time);
    fc.print_flow_features(outputfilename);
    fc.print_sampled_packet_count(outputfilename,sampled_pkt_cnt);

    return 0;
}


int counter=0;
int cnt = 0;
double r = 0;
flow_t* me;
int sampler_cnt=0;

//est = get_khat(threshold, vector_size);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *buffer)
{
   //fixing buffer offset
    buffer = buffer + 14;
    //Careful about the above line

    flowid_t flowid =  get_flowid(buffer);
    if(flowid.proto!=6 && flowid.proto!=17) {return;}
    
    string flowid_str = fc.get_flowid_str(flowid);
    size_t hash_value = hash<string>()(flowid_str);
    

    if (hash_value != 0)
    {

        cnt = hash_value%linearCounter_array_size;
        ffs_counter[cnt]++;
        
        if(ffs_counter[cnt]>param_l)
            ffs_counter[cnt]=0; // modulo l operation
        else if(ffs_counter[cnt]<param_s)
        {
            ++sampler_cnt;
            if(sampler_cnt==est)
            {
                fc.ht_insert_est(flowid,est,buffer,header->ts);
                sampled_pkt_cnt++;
                sampler_cnt=0;
                est=(rand()%(2*SAMPLING_RATE-1))+1;
            }
        }
   }
}

