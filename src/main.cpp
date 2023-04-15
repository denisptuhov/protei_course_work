#include "ethDevice.h"
#include "additional.h"

int main(){
   setup_logger();

   ethDevice dev;
   auto res = dev.setup();
   if (res != SETUP_RESULT_TYPE::SUCCESS)
      return 2;


   hostInfoVec hosts;
   std::mutex mtx;
   ether_addr if_mac = dev.get_if_mac();

   handler_args args(&hosts, &if_mac, &mtx);

   std::thread thr(
      pcap_loop, 
      dev.get_handler(), 
      0, 
      my_packet_handler, 
      reinterpret_cast<u_char*>(&args)
   );
   std::thread thr2(
      print_hosts_info, 
      &hosts, 
      &mtx
   );

   thr.join();
   thr2.join();
}
