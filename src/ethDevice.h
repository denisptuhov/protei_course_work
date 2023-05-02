#include <pcap.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <string>
#include <cstring>
#include <spdlog/spdlog.h>


enum class SETUP_RESULT_TYPE{
      SUCCESS,
      OPEN_HANDLER_ERROR,
      COMPILE_FILTER_ERROR,
      APPLY_FILTER_ERROR,
};

class ethDevice{
public:
   explicit ethDevice();
   ~ethDevice();

   void setup_dev_macAdr();
   SETUP_RESULT_TYPE setup();

   pcap_t* get_handler();
   ether_addr get_if_mac();

private:
   std::string dev;
   pcap_t* handler;
   ether_addr if_mac;
};
