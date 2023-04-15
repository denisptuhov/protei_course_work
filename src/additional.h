#include <iostream>
#include <iomanip>
#include <spdlog/sinks/rotating_file_sink.h>
#include "hostInfo.h"

struct handler_args{
   explicit handler_args(hostInfoVec* hosts, ether_addr* if_mac, std::mutex* mtx) : 
      hosts(hosts),
      if_mac(if_mac),
      mtx(mtx) {}

   hostInfoVec* hosts;
   ether_addr* if_mac;
   std::mutex* mtx;
};

void setup_logger();

bool isConvertKBtoMB(int size);
double calculate_output_size(int size, int f);

void print_hosts_info(hostInfoVec* hosts, std::mutex* mtx);
void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char *packet);