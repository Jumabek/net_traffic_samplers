#include <stdint.h>
#include<pcap.h>
#define MCS_IN_SEC 1000000
#define FLOWTIMEOUT 120
#define TCP_PROTOCOL 6

int has_fin_flag(const u_char *buffer);
int has_syn_flag(const u_char *buffer);
int has_rst_flag(const u_char *buffer);
int has_push_flag(const u_char *buffer);
int has_ack_flag(const u_char *buffer);
int has_urg_flag(const u_char *buffer);
/*
int has_ece_flag(const u_char *buffer);
int has_cwr_flag(const u_char *buffer);
*/
int get_payload_len(const u_char *buffer, uint32_t proto);
int get_header_len(const u_char *buffer, uint32_t proto);

double max(double a, double b);
double min(double a, double b);

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
struct timeval get_max(struct timeval a, struct timeval b);
