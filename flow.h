#include <stdint.h>
#include "pcap.h"

typedef struct flowid {
    uint32_t is;
    uint32_t id;
    uint32_t proto;
    uint32_t sp;
    uint32_t dp;
} flowid_t;


typedef struct  flow {
    uint32_t hash_value;
    //float temp_counter;
    uint32_t is;
    uint32_t id;
    uint8_t proto;
    uint16_t sp;
    uint16_t dp;
    //later used for feduration
    struct timeval first_packet_fts;
    struct timeval first_packet_bts;
    struct timeval last_packet_fts;
    struct timeval last_packet_bts;

    float total_fpackets;
    float total_bpackets;

    float total_fpktl;
    float total_bpktl;

    float min_fpktl;
    float min_bpktl;

    float max_fpktl;
    float max_bpktl;

    /* no need to store because we use total_fpktl and total_fpacket to obtain mean_fpktl in any time
    float mean_fpktl;
    float mean_bpktl;
    float mean_fpktl_est;
    float mean_bpktl_est;
    */

    //need the following for std
    float total_fpktl_sq;
    float total_bpktl_sq;
    /*https://arxiv.org/pdf/1802.09089.pdf Feature Extractor section
        at any given time:
            mean_size = lsum/n
            sigma_sq = |sumsq/n-(lsum/n)^2|
            std = sq_root(sigma_sq)
    */

    float total_fiat;
    float total_biat;
    float min_fiat;
    float min_biat;
    //we find time between two sampled packets then divide by (est-1)

    float max_fiat;
    float max_biat;

    //float mean_fiat = total_fiat/(total_fpkt-1)
    //float mean_fiat_est = total_fiat_est/(total_fpkt_est-1)
    //we calculate it when printing flow feature

    //following is necessary for computing std
    float fiat_sq;
    float biat_sq;
    //fiat_sq = est*(cur_fiat/est)^2
    //std_fiat=sqrt(fiat_sigma_sq)

    int fpsh_cnt;
    int bpsh_cnt;

    int furg_cnt;
    int burg_cnt;

    long total_fhlen;
    long total_bhlen;

    //float fPktsPerSecond;
    //float bPktsPerSecond;

    //float flowPktsPerSecond;
    //float flowBytesPerSecond;

    //min_flowpktl = min(min_fpktl,min_bpktl)
    //max_flowpktl = max(max_fpktl,max_bpktl)

	//mean_flowpktl = (total_fpktl+total_bpktl)/(total_fpkt+total_bpkt)

    //need the following for std_flowpktl
    float total_flowpktl_sq;
    /*https://arxiv.org/pdf/1802.09089.pdf Feature Extractor section
        at any given time:
            mean_size = lsum/n
            sigma_sq = |sumsq/n-(lsum/n)^2|
            std = sq_root(sigma_sq)
    */

    //min_flowiat=min(min_fiat,min_biat);

    //max_flowiat=max(max_fiat,max_biat);

    //float mean_flowiat = (total_fiat+total_biat)/(total_fpkt-1)
    //float mean_flowiat_est = (total_fiat_est+total_biat_est)/(total_fpkt_est-1+total_bpkt_est-1)
    //we calculate it when printing flow feature

    //following is necessary for computing std
    //fiat_sq += cur_fiat^2
    //fiat_est_sq = est*(cur_fiat_est/est)^2
    //flowiat_sq = fiat_sq+biat_sq
    //flowiat_est_sq = fiat_est_sq+biat_est_sq

    int flow_fin;
    int flow_syn;
    int flow_rst;
    int flow_psh;
    int flow_ack;
    int flow_urg;
    int flow_cwr;
    int flow_ece;

    //downUpRatio=total_bpktl/total_fpktl;

     /* no need to store below features because we use total_pktl and total_pkt to obtain mean_pktl in any time
    float mean_pktl;
    float mean_pktl_est;
    */

    int act_data_pkt_forward; // Count of packets with at least 1 byte of TCP data payload in the forward direction
    float min_seg_size_forward; //cicflowmeter implementation, min headersize in forward direction
} flow_t;

