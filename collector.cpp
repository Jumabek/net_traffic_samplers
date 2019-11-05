#include "collector.h"
#include <stdio.h>
#include <string.h>

#define MAX_TCP_HEADER_SIZE 60

using namespace std;

void Collector::ht_insert_est(flowid_t flowid, float est, const u_char *buffer, struct timeval ts)
{
    //check if flow is in active_flows
    string flowid_str = get_flowid_str(flowid);

    if(active_flows.find(flowid_str)!=active_flows.end())// flow is in active_flows 
    {
        flow_t flow = active_flows[flowid_str];
        int forward = flow.is==flowid.is;
        struct timeval diff;
        timeval_subtract(&diff,&ts,&(flow.first_packet_fts));
        if(diff.tv_sec>FLOWTIMEOUT)
        {
            //1. move to finished list
            //2. remove from active list
            //3. create new flow with packet-in-process in active list

            //1.
            finished_flows.push_back(flow);
            //2.
            active_flows.erase(flowid_str);
            
            //3.
            flow_t new_flow;
            new_flow = initialize_features(new_flow,buffer,ts,flowid);
            forward = 1;
            new_flow = increment_features(new_flow,est,buffer,forward,ts);
            active_flows.insert(make_pair(flowid_str,new_flow));
        }
        else if(has_fin_flag(buffer))
        {
            //1. add pkt-in-process
            //2. move to finished flow list
            //3. remove from active flow
            flow = increment_features(flow,est,buffer,forward,ts);

            finished_flows.push_back(flow);
            active_flows.erase(flowid_str);
        }
        else{
            flow = increment_features(flow,est,buffer,forward, ts);
            active_flows[flowid_str] = flow;
        }
    }
    else
    {
        flow_t flow;
        flow = initialize_features(flow,buffer,ts,flowid);
        
        //printf("flow.proto = %"PRIu32"\n",flow.proto);
        int forward=1;
        flow = increment_features(flow,est,buffer,forward, ts);

        //printf("flow.proto = %"PRIu32"\n\n",flow.proto);
        active_flows.insert(make_pair(flowid_str,flow));
    }

    return;
}

int Collector::get_num_concurrent_flows()
{
    return active_flows.size();
}

void Collector::print_flow_features(char* filename)
{
        FILE *f;
        //char log[100] = "/home/isrl/L1/L1_juma_monday.txt";
        printf("Opening %s \n",filename);
        f = fopen(filename, "w");
        flow_t* me;

        int non_zero_entry = 0;
        //writing header
        fprintf(f,"%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n","Flowid","Source IP","Source Port","Destination IP","Destination Port","Protocol", "Timestamp","Feduration", "total_fpackets", "total_bpackets", "total_fpktl","total_bpktl","min_fpktl","min_bpktl","max_fpktl","max_bpktl","mean_fpktl","mean_bpktl","std_fpktl","std_bpktl","total_fiat","total_biat","min_fiat","min_biat","max_fiat","max_biat","mean_fiat","mean_biat","std_fiat","std_biat","fpsh_cnt","bpsh_cnt","furg_cnt","burg_cnt","total_fhlen","total_bhlen","fPktsPerSecond","bPktsPerSecond","flowPktsPerSecond","flowBytesPerSecond","min_flowpktl","max_flowpktl","mean_flowpktl","std_flowpktl","min_flowiat","max_flowiat","mean_flowiat","std_flowiat","flow_fin","flow_syn","flow_rst", "flow_psh", "flow_ack", "flow_urg", "downUpRatio", "Act_data_pkt_forward","min_seg_size_forward");

        unordered_map<string,flow_t>:: iterator itr;
        for(itr = active_flows.begin(); itr!=active_flows.end();itr++){
            me = &(itr->second);
            if(me!=NULL){
                if (me->total_fpackets + me->total_bpackets < 1) continue;
                non_zero_entry++;
                me = fix_flow(me);
                write_flow(f,me);
            }
        }

        printf("written %d active flows \n",non_zero_entry);

        non_zero_entry=0;
        list<flow_t> :: iterator itr2;
        for(itr2 = finished_flows.begin(); itr2!=finished_flows.end();itr2++){
            me = &*itr2;
            if(1==1){
                if (me->total_fpackets + me->total_bpackets < 1) continue;
                non_zero_entry++;
                me = fix_flow(me);
                write_flow(f,me);
            }
        }

        printf("Written %d  finished flows \n\n",non_zero_entry);
        fclose(f);
}

long Collector::print_selected_flow_features(char* filename,float z,float c, float n)
{
        FILE *f;
        //char log[100] = "/home/isrl/L1/L1_juma_monday.txt";
        printf("Opening %s \n",filename);
        f = fopen(filename, "w");
        flow_t* me;
        long sampled_pkt_cnt= 0;
        int non_zero_entry = 0;
        //writing header
        //
        //
        float x;
        fprintf(f,"%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n","Flowid","Source IP","Source Port","Destination IP","Destination Port","Protocol", "Timestamp","Feduration", "total_fpackets", "total_bpackets", "total_fpktl","total_bpktl","min_fpktl","min_bpktl","max_fpktl","max_bpktl","mean_fpktl","mean_bpktl","std_fpktl","std_bpktl","total_fiat","total_biat","min_fiat","min_biat","max_fiat","max_biat","mean_fiat","mean_biat","std_fiat","std_biat","fpsh_cnt","bpsh_cnt","furg_cnt","burg_cnt","total_fhlen","total_bhlen","fPktsPerSecond","bPktsPerSecond","flowPktsPerSecond","flowBytesPerSecond","min_flowpktl","max_flowpktl","mean_flowpktl","std_flowpktl","min_flowiat","max_flowiat","mean_flowiat","std_flowiat","flow_fin","flow_syn","flow_rst", "flow_psh", "flow_ack", "flow_urg", "downUpRatio", "Act_data_pkt_forward","min_seg_size_forward");

        unordered_map<string,flow_t>:: iterator itr;
        for(itr = active_flows.begin(); itr!=active_flows.end();itr++){
            me = &(itr->second);
            x = me->total_fpackets + me->total_bpackets;
            if(isFlowSelected(z,c,n,x))
            {
                    sampled_pkt_cnt+= x;
                    non_zero_entry++;
                    me = fix_flow(me);
                    write_flow(f,me);
            }
        }

        printf("Written %d active flows \n",non_zero_entry);

        non_zero_entry=0;
        list<flow_t> :: iterator itr2;
        for(itr2 = finished_flows.begin(); itr2!=finished_flows.end();itr2++){
            me = &*itr2;
            x = me->total_fpackets + me->total_bpackets;
            if(isFlowSelected(z,c,n,x)){
                sampled_pkt_cnt+= x;
                non_zero_entry++;
                me = fix_flow(me);
                write_flow(f,me);
            }
        }

        printf("Written %d completed flows \n\n",non_zero_entry);
        fclose(f);
        return sampled_pkt_cnt;
}

flow_t* Collector::fix_flow(flow_t* me)
{
    if(me->total_fpackets==0)
    {
        me->min_fpktl=-1;
        me->max_fpktl=-1;
        me->min_fiat=-1;
        me->max_fiat=-1;
        me->min_seg_size_forward=-1;
    }
    if(me->total_bpackets==0)
    {
        me->min_bpktl=-1;
        me->max_bpktl=-1;
        me->min_biat=-1;
        me->max_biat=-1;
    }

    if(me->min_fpktl==65535)
        me->min_fpktl=-1;
    if(me->min_bpktl==65535)
        me->min_bpktl=-1;

    if(me->min_fiat==(FLOWTIMEOUT*MCS_IN_SEC+1))
        me->min_fiat=-1;

    if(me->min_biat==(FLOWTIMEOUT*MCS_IN_SEC+1))
        me->min_biat=-1;

    if(me->total_fiat==0)
    {
        me->total_fiat=-1;
        me->min_fiat=-1;
        me->max_fiat=-1;
    }
    if(me->total_biat==0)
    {
        me->total_biat=-1;
        me->min_biat=-1;
        me->max_biat=-1;
    }

    return me;
}



void Collector::write_flow(FILE *f, flow_t *me)
{
        uint32_t is,id,sp,dp,proto;
        struct in_addr saddr;
        struct in_addr daddr;

                is = me->is;
                id = me->id;
                sp = me->sp;
                dp = me->dp;
                proto = me->proto;

                saddr.s_addr = is;
                daddr.s_addr = id;

                char flowid_str[100];
                int j = sprintf(flowid_str,"%s-",inet_ntoa(saddr));//we cannot print two inet_ntoa in one printf
                j += sprintf(flowid_str+j,"%s-",inet_ntoa(daddr));

                j += sprintf(flowid_str+j,"%"PRIu32 "-",me->sp);

                j += sprintf(flowid_str+j,"%"PRIu32 "-",me->dp);

                j += sprintf(flowid_str+j," %"PRIu32" ",me->proto);

                fprintf(f,"%s,",flowid_str);                        //1 flowid
                fprintf(f,"%s,",inet_ntoa(saddr));                  //2 Src IP
                fprintf(f,"%" PRIu32 ",",me->sp);                    //3 Src port
                fprintf(f,"%s,",inet_ntoa(daddr));                  //4 Dst IP
                fprintf(f,"%" PRIu32 ",",me->dp);                   //5 Dst port
                fprintf(f,"%" PRIu32 "," ,me->proto);               //6 Proto


                char tmbuf[64], buf[64];
                int timezone_offset = 13*60*60;
                struct timeval tv = me->first_packet_fts;
                tv.tv_sec = tv.tv_sec - timezone_offset;
                struct tm *nowtm = localtime(&(tv.tv_sec));
                strftime(tmbuf, sizeof tmbuf, "%d/%m/%Y %H:%M:%S %p", nowtm);

                fprintf(f,"%s,",tmbuf);                                     //7  TimeStamp
                struct timeval feduration;
                struct timeval last_packet_ts = get_max(me->last_packet_fts,me->last_packet_bts);

                timeval_subtract(&feduration, &last_packet_ts,&(me->first_packet_fts));
                long feduration_mcs = feduration.tv_sec*MCS_IN_SEC+feduration.tv_usec;
                fprintf(f,"%ld,",feduration_mcs);                                       //8 Feduration


                fprintf(f,"%f,", (me->total_fpackets));                     //9 Total Packets in Forward direction
                fprintf(f,"%f,",me->total_bpackets);                        //10 Total ../..

                fprintf(f,"%.0f,",me->total_fpktl);                       //11
                fprintf(f,"%.0f,",me->total_bpktl);                         //12
                fprintf(f,"%.0f,",me->min_fpktl);                 //13                    
                fprintf(f,"%.0f,",me->min_bpktl);                 //14
                fprintf(f,"%.0f,",me->max_fpktl);                 //15
                fprintf(f,"%.0f,",me->max_bpktl);                 //16

                if(me->total_fpackets>0)
                    fprintf(f,"%.0f,",me->total_fpktl/me->total_fpackets);          //17 mean fpktl
                else
                    fprintf(f,"%d,",-1);          //17

                if(me->total_bpackets>0)
                    fprintf(f,"%.0f,",me->total_bpktl/me->total_bpackets);          //18 mean bpktl
                else
                    fprintf(f,"%d,",-1);          //18

                double nf=me->total_fpackets;
                double l = me->total_fpktl;
                double sq = me->total_fpktl_sq;
                double sigma_sq = fabs(sq/nf - (l/nf)*(l/nf));
                float std_fpktl = sqrt(sigma_sq);
                if(me->total_fpackets >0)
                    fprintf(f,"%.2f,",std_fpktl);                             // 19 std_fpktl Standard deviation size of packet in forward direction
                else
                    fprintf(f,"%d,",-1);                                       //19

                double nb=me->total_bpackets;
                l = me->total_bpktl;
                sq = me->total_bpktl_sq;
                sigma_sq = fabs(sq/nb - (l/nb)*(l/nb));
                float std_bpktl = sqrt(sigma_sq);
                if(me->total_bpackets>0)
                    fprintf(f,"%.0f,",std_bpktl);                             //20 std_bpktl Standard deviation size of packet in backward direction
                else
                    fprintf(f,"%d,", -1);                                      //20

                long total_fiat_mcs = me->total_fiat;
                fprintf(f,"%ld,",total_fiat_mcs);                         //21 total_fiat total inter arrival time between packets

                long total_biat_mcs = me->total_biat;
                
                fprintf(f,"%ld,",(long)me->total_biat);                          //22 total_biat IAT between backward packets

                long mcs = me->min_fiat;   //min fiat
                fprintf(f,"%ld,",mcs);                                      //23

                mcs = me->min_biat;   //min biat
                fprintf(f,"%ld,",mcs);                                      //24

                mcs = me->max_fiat;   //max fiat
                fprintf(f,"%ld,",mcs);                                      //25

                mcs = me->max_biat;   //max biat
                fprintf(f,"%ld,",mcs);                                      //26

                if(me->total_fiat>0)
                {
                    long mean_fiat_mcs = total_fiat_mcs/me->total_fpackets;
                    fprintf(f,"%ld,",mean_fiat_mcs);                            //27  mean fiat
                }
                else
                    fprintf(f,"%d,",-1);                                      //27
                if( me->total_biat>0)
                {
                    long mean_biat_mcs = total_biat_mcs/me->total_bpackets;
                    fprintf(f,"%ld,",mean_biat_mcs);                            //28 mean biat
                }
                else
                    fprintf(f,"%d,", -1);                                     //28

                sq = me->fiat_sq;
                //nf = me->total_fpackets;
                if(me->total_fiat>0)
                {
                    l = me->total_fiat;
                    sigma_sq = fabs(sq/nf- (l/nf)*(l/nf));
                    double std_fiat = sqrt(sigma_sq);
                    fprintf(f,"%.2f,",std_fiat);                                 //29 std fiat
                }
                else
                    fprintf(f,"%d,",-1);                                      //29

                sq = me->biat_sq;
                //nb = me->total_bpackets;
                if(me->total_biat>0)
                {
                    l = me->total_biat;
                    sigma_sq = fabs(sq/nb- (l/nb)*(l/nb));
                    double std_biat = sqrt(sigma_sq);
                    fprintf(f,"%.2f,",std_biat);                                 //30 std biat
                }
                else
                    fprintf(f,"%d,",-1);                                         //30

                fprintf(f,"%d,",me->fpsh_cnt);                              //31 fpsh_cnt
                fprintf(f,"%d,",me->bpsh_cnt);                              //32 bpsh_cnt

                fprintf(f,"%d,",me->furg_cnt);                              //33 furg_cnt
                fprintf(f,"%d,",me->burg_cnt);                              //34 burg_cnt

                fprintf(f,"%ld,",me->total_fhlen);                          //35
                fprintf(f,"%ld,",me->total_bhlen);                          //36

                if(feduration_mcs>0)
                {
                    double fPktsPerSecond = me->total_fpackets/(feduration_mcs/1000000.); // fPktsPerSecond
                    fprintf(f,"%.2f,",fPktsPerSecond);                          //37
                    double bPktsPerSecond = me->total_bpackets/(feduration_mcs/1000000.); // bPktsPerSecond
                    fprintf(f,"%.2f,",bPktsPerSecond);                          //38
                    double flowPktsPerSecond = (me->total_fpackets + me->total_bpackets)/(feduration_mcs/1000000.);
                    fprintf(f,"%.2f,",flowPktsPerSecond);                       //39 flowPktsPerSecond

                    double flowBytesPerSecond = (me->total_fpktl + me->total_bpktl)/(feduration_mcs/1000000.);
                    fprintf(f,"%.2f,",flowBytesPerSecond);                       //40 flowBytesPerSecond

                }
                else
                {
                    fprintf(f,"%d,",-1);                                     //37
                    fprintf(f,"%d,",-1);                                     //38
                    fprintf(f,"%d,",-1);                                     //39
                    fprintf(f,"%d,",-1);                                     //40
                }

                fprintf(f,"%.2f,",min(me->min_fpktl,me->min_bpktl));                //41 min_flowpktl
                fprintf(f,"%.2f,",max(me->max_fpktl,me->max_bpktl));                //42 max_flowpktl

                if(me->total_fpktl+me->total_bpktl > 0)
                {

                    float mean_flowpktl = (me->total_fpktl + me->total_bpktl)/(me->total_fpackets + me->total_bpackets);
                    fprintf(f,"%.2f,",mean_flowpktl);                                   //43 mean_flowpktl
                    double n = me->total_fpackets + me->total_bpackets;
                    sigma_sq = fabs(me->total_flowpktl_sq/n-mean_flowpktl*mean_flowpktl);
                    float std_flowpktl = sqrt(sigma_sq);
                    fprintf(f,"%.2f,",std_flowpktl);                                    //44 std_flowpktl
                }
                else 
                {
                    fprintf(f,"%d,",-1);
                    fprintf(f,"%d,",-1);
                }

                fprintf(f,"%.2f,",min(me->min_fiat,me->min_biat));                  //45 min flowiat

                fprintf(f,"%.2f,",max(me->max_fiat,me->max_biat));                  //46 max_flowiat

                if(me->total_fiat+me->total_biat>0)
                {
                    double n = me->total_bpackets + me->total_fpackets;
                    long mean_flowiat = (me->total_fiat+me->total_biat)/n;
                    fprintf(f,"%ld,", mean_flowiat);                                   //47 mean_flowiat
                    double sum_sq = me->fiat_sq + me->biat_sq;
                    sigma_sq = fabs(sum_sq/n-mean_flowiat*mean_flowiat);
                    double std_flowiat = sqrt(sigma_sq);
                    fprintf(f,"%.2f,", std_flowiat);                                    //48 std_flowiat
                }
                else
                {
                    fprintf(f,"%d,",-1);                         //47
                    fprintf(f,"%.2f,",-1.);                             //48
                }

                fprintf(f,"%d,",me->flow_fin);                                      //49
                fprintf(f,"%d,",me->flow_syn);                                      //50
                fprintf(f,"%d,",me->flow_rst);                                      //51
                fprintf(f,"%d,",me->flow_psh);                                      //52
                fprintf(f,"%d,",me->flow_ack);                                      //53
                fprintf(f,"%d,",me->flow_urg);                                      //54

                if(me->total_fpktl > 0)
                    fprintf(f,"%.2f,",(double)me->total_bpktl/(double)me->total_fpktl);                 //55 downUpRatio
                else
                    fprintf(f,"%d,",-1);                 //58 downUpRatio

                fprintf(f,"%d,",me->act_data_pkt_forward);                          //56 count of pacekts with at least 1 byte of TCP data payload
                fprintf(f,"%.2f\n",me->min_seg_size_forward);                        //57 min header size in forward direction

                return;
}


bool Collector::isFlowSelected(float z, float c, float n, float x)
{
    if(x<=z)
    {
        if (rand()%(int)(1./c)==0) return 1;
        else return 0;
    }
    else{
        if( rand()%(int)(n*x/z)==0) return 1;
        else return 0;
        return 0;
    }
}


flow_t Collector::initialize_features(flow_t me,const u_char *buffer,struct timeval ts, flowid_t flowid){
    me.is = flowid.is;
    me.sp = flowid.sp;
    me.id = flowid.id;
    me.dp = flowid.dp;
    me.proto = flowid.proto;

    me.first_packet_fts = ts;
    me.last_packet_fts = ts;
    me.first_packet_bts = ts; //not used
    me.last_packet_bts = ts;//updated


    me.total_fpackets = 0;
    me.total_bpackets = 0;

    me.total_fpktl=0;
    me.total_bpktl=0;

    me.min_fpktl=65535;
    me.min_bpktl=65535;
    me.max_fpktl=0;
    me.max_bpktl=0;

    me.total_fpktl_sq=0;
    me.total_bpktl_sq=0;

    me.total_fiat=0;
    me.total_biat=0;
    me.min_fiat=FLOWTIMEOUT*MCS_IN_SEC+1; //+1 is for edge case
    me.min_biat=FLOWTIMEOUT*MCS_IN_SEC+1;
    me.max_fiat=0;
    me.max_biat=0;

    me.fiat_sq=0; //is used for computing fiat_std;
    me.biat_sq =0; //for std_biat

    me.fpsh_cnt=0;
    me.bpsh_cnt=0;
    me.furg_cnt=0;
    me.burg_cnt=0;

    me.total_fhlen = 0;
    me.total_bhlen = 0;

    me.total_flowpktl_sq=0;//for std_flowpktl

    me.flow_fin=0;
    me.flow_syn=0;
    me.flow_rst=0;
    me.flow_psh=0;
    me.flow_ack=0;
    me.flow_urg=0;
    me.flow_cwr=0;
    me.flow_ece=0;

    me.act_data_pkt_forward=0;
    me.min_seg_size_forward = MAX_TCP_HEADER_SIZE;
    
    return me;
}

flow_t Collector::increment_features(flow_t me,float est, const u_char *buffer,int forward, struct timeval ts)
{
    float data_len =  get_payload_len(buffer,me.proto);
    float header_len =  get_header_len(buffer,me.proto);
    if(forward==1)
    {
        me.total_fpackets+=est;
        me.total_fpktl+= data_len*est;
        me.min_fpktl = min(me.min_fpktl,data_len);
        me.max_fpktl = max(me.max_fpktl,data_len);

        me.total_fpktl_sq+=data_len*data_len*est;
        struct timeval iat_ts;
        timeval_subtract(&iat_ts, &ts, &(me.last_packet_fts));
        long iat = (iat_ts.tv_sec* MCS_IN_SEC + iat_ts.tv_usec)/est;
        me.total_fiat += iat*est;

        me.min_fiat = min(me.min_fiat,iat);
        me.max_fiat= max(me.max_fiat,iat);

        me.fiat_sq+=iat*iat*est;
        if (me.proto == TCP_PROTOCOL)
        {
            me.fpsh_cnt+= has_push_flag(buffer);
            me.furg_cnt+= has_urg_flag(buffer);
        }
        me.total_fhlen+=header_len*est;
        me.last_packet_fts=ts;
    }
    else
    {
        me.total_bpackets+=est;
        me.total_bpktl+=data_len*est;
        me.min_bpktl = min(me.min_bpktl,data_len);
        me.max_bpktl = max(me.max_bpktl,data_len);

        me.total_bpktl_sq+=data_len*data_len*est;

        struct timeval iat_ts;
        if (me.total_bpackets>est)
        {
            timeval_subtract(&iat_ts, &ts,&(me.last_packet_bts));
            long iat = (iat_ts.tv_sec*MCS_IN_SEC + iat_ts.tv_usec)/est;

            me.total_biat +=iat*est;

            me.min_biat = min(me.min_biat,iat);
            me.max_biat= max(me.max_biat,iat);

            me.biat_sq+=iat*iat*est;
        }
        me.total_bhlen += header_len*est;
        me.last_packet_bts = ts;
    }

    me.total_flowpktl_sq = data_len*data_len*est;
    if(me.proto == TCP_PROTOCOL)
    {
        me.flow_fin += has_fin_flag(buffer);
        me.flow_syn += has_syn_flag(buffer);
        me.flow_rst += has_rst_flag(buffer);
        me.flow_psh += has_push_flag(buffer);
        me.flow_ack += has_ack_flag(buffer);
        me.flow_urg += has_urg_flag(buffer);
        //me->flow_cwr += has_cwr_flag(buffer);
        //me->flow_ece += has_ece_flag(buffer);
    }
    if (data_len>0)
        me.act_data_pkt_forward+=est;
    me.min_seg_size_forward = min(me.min_seg_size_forward,header_len);
    
    return me;
}

void Collector::print_sampled_packet_count(char* filename,long cnt)
{
    char temp[200];
    strcpy(temp,filename);
    char* filename_full = strncat(temp,".spc",4);
    
    FILE* f = fopen(filename_full, "w");
    fprintf(f,"%ld\n",cnt);
    fclose(f);
}

int Collector::print_num_concurrent_flows(char* filename,int n)
{
    char temp[200];
    strcpy(temp,filename);
    char* filename_full  = strncat(temp,".nflows",7);
    FILE* f = fopen(filename_full, "w");
    fprintf(f,"%d\n",n);
    fclose(f);
}
