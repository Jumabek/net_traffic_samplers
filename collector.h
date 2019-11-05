#include <iostream>
#include <unordered_map>
#include <string>
#include <math.h>
#include <limits.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <list>
#include "flow.h"
#include "helper.h"

using namespace std;

class Collector{
    private:
        unordered_map<string,flow_t> active_flows; // <flowid_str,flow>
        list<flow_t> finished_flows; // <flowid_str,flow>

        flow_t initialize_features(flow_t me, const u_char *buffer,struct timeval ts,flowid_t flowid);
        flow_t increment_features(flow_t me,float est, const u_char *buffer,int forward, struct timeval ts);
        flow_t* fix_flow(flow_t* flow);
        void write_flow(FILE* f, flow_t* me);
        bool isFlowSelected(float z, float c, float n, float x);

    public:
        void ht_insert_est(flowid_t flowid, float est, const u_char *buffer, struct timeval ts);
        int get_num_concurrent_flows();
        void print_flow_features(char* filename);
        long print_selected_flow_features(char* filename,float z,float c, float n);
        
        int is_forward(flowid_t flowid)
        {
            if(flowid.sp>flowid.dp)
                return 1;
            else
                return 0;
        }

        string get_flowid_str(flowid_t flowid)
        {
            if(flowid.sp>flowid.dp) // client always has bigger port number( credit to Jiyuu)
                return to_string(flowid.is)+"-"+to_string(flowid.id) + "-" + to_string(flowid.sp) + "-" + to_string(flowid.dp) + "-" + to_string(flowid.proto);
            else
                return to_string(flowid.id)+"-"+to_string(flowid.is) + "-" + to_string(flowid.dp) + "-" + to_string(flowid.sp) + "-" + to_string(flowid.proto);

        }
        void print_sampled_packet_count(char* filename, long cnt);
        int print_num_concurrent_flows(char* filename, int n);
};

