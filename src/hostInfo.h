#include <vector>
#include <string>
#include <spdlog/spdlog.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

class hostInfo;

using hostInfoVec = std::vector<hostInfo>;

enum class HOSTNAME_DETER_RESULT_TYPE{
   SUCCEES,
   IPv4_PROTOCOL_NAME_NOT_FOUND,
   IPv6_PROTOCOL_NAME_NOT_FOUND
};

class hostInfo{
public:
   explicit hostInfo() :
      count_in(0),
      count_out(0),
      in_package_size(0),
      out_package_size(0),
      total_package_size(0) {}

   void make_hostname_pretty();

   HOSTNAME_DETER_RESULT_TYPE find_hostname(const ip* ip_header, char who);
   void insert_data(int packet_size, char who);

   std::string get_hostname() const;
   u_int get_count_in() const;
   u_int get_count_out() const;
   double get_in_package_size() const;
   double get_out_package_size() const;
   double get_total_package_size() const;
   void set_hostname(std::string);

   bool operator==(const hostInfo& host) const;

private:
   u_int count_in;
   u_int count_out;

   double in_package_size;
   double out_package_size;
   double total_package_size;
   std::string hostname;

};