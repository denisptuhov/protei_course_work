#include "additional.h"

/*
 * Функция setup_logger() создает и настраивает ротирующий логгер (logger) с использованием библиотеки spdlog.
 * Логгер называется "packet_logger" и будет записывать логи в файл "logs/packet_log.txt".
 * Максимальный размер одного лог-файла ограничен 2 МБ (1048576 * 2 байт).
 * Максимальное количество файлов логов ограничено одним файлом (max_files = 1).
 * Логгер создается с использованием многопоточного (thread-safe) режима работы (spdlog::rotating_logger_mt).
*/

void setup_logger(){
   auto max_size = 1048576 * 2;
   auto max_files = 1;
   auto logger1 = spdlog::rotating_logger_mt("packet_logger", "../logs/packet_log.txt", max_size, max_files);
}

/*
 * Данная функция принимает размер пакета в КB и проверяет необходимо ли перевести их в МB.
 * Возвращаемое значение - результат проверки.
*/
bool isConvertKBtoMB(int size){
   return size / 1024.0 > 0.8;
}

/*
 * Данная функция принимает размер пакета в КБ и при необходимости переводит их в МB
*/
double calculate_output_size(int size, int f){
   return (f) ? size / 1024.0 : size;
}

/*
 * Функция print_hosts_info() предназначена для вывода статистики информации о хостах в консоль.
 * Функция использует мьютекс mtx для обеспечения потокобезопасного доступа к вектору хостов.
 * Затем происходит циклический вывод информации о хостах в виде строк таблицы, отформатированных по заданным значениям.
 * Если вектор хостов пуст, выводится критическое сообщение в лог о пустом векторе, и функция ожидает 5 секунд перед рекурсивным вызовом самой себя.
 * После вывода информации функция разблокирует мьютекс, ожидает 5 секунд, 
 * и рекурсивно вызывает саму себя для циклического обновления статистики на консоли.
*/
void print_hosts_info(hostInfoVec* hosts, std::mutex* mtx){
   spdlog::get("packet_logger")->debug("Start printing");

   auto& mtx_ = *mtx;
   std::unique_lock<std::mutex> lock(mtx_);
   std::cout << std::left;

   if (hosts->empty()){
      spdlog::get("packet_logger")->critical("Hosts map empty, waiting another 5 sec...");
      lock.unlock();
      std::this_thread::sleep_for(std::chrono::seconds(5));
      print_hosts_info(hosts, mtx);
      return;
   }

   // Максимальные длины строк для функции setw
   const int max_packet_part_size = 30;
   const int max_traffic_part_size = 40;
   const int max_hostname_size = 25;
   char packet_part_output[max_packet_part_size];
   char traffic_part_output[max_traffic_part_size];

   bool f_total, f_in, f_out;
   for (auto& host: *hosts){
      // Данные флаги указывают на необходимость перевода соответствующих значений из KB в MB
      f_total = isConvertKBtoMB(host.get_total_package_size());
      f_in = isConvertKBtoMB(host.get_in_package_size());
      f_out = isConvertKBtoMB(host.get_out_package_size());
      spdlog::get("packet_logger")->info("Is converting neccessary for statistics: {} in, {} out, {} total", f_in, f_out, f_total);

      // Форматированный вывод в строки, представляющие собой информацию о кол-ве пакетов и размере трафика 
      int n = sprintf(
         packet_part_output,
         "Packets: %d(%d OUT/%d IN)",
         host.get_count_in() + host.get_count_out(),
         host.get_count_in(),
         host.get_count_out()
      );
      
      n = sprintf(
         traffic_part_output,
         "Traffic: %.1f%s(%.1f%s OUT/%.1f%s IN)",
         calculate_output_size(host.get_total_package_size(), f_total),
         (f_total) ? "MB" : "KB",
         calculate_output_size(host.get_out_package_size(), f_out),
         (f_out) ? "MB" : "KB",
         calculate_output_size(host.get_in_package_size(), f_in),
         (f_in) ? "MB" : "KB"
      );

      std::cout << std::setw(max_hostname_size) << host.get_hostname();
      std::cout << std::setw(max_packet_part_size) << packet_part_output;
      std::cout << std::setw(max_traffic_part_size) << traffic_part_output << std::endl;
   }
   std::cout << std::endl << std::endl;

   lock.unlock();

   spdlog::get("packet_logger")->debug("End printing");

   std::this_thread::sleep_for(std::chrono::seconds(5));
   print_hosts_info(hosts, mtx);
}

/*
 * Функция my_packet_handler является хэндлером для функции pcap_loop, предназначенной для захвата сетевых пакетов.
 * Она выполняет обработку захваченных пакетов, анализирует их содержимое.
 * Осуществляет запись информации о хостах, их именах и размере передаваемых/принимаемых данных. 
 * Функция также выполняет проверки на типы пакетов и их направления (входящий/исходящий) на основе MAC-адресов и IP-заголовков. 
*/

void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char *packet){
   spdlog::get("packet_logger")->info("Received packet with {}B len", header->len);
   
   // Распаковка аргументов
   handler_args* h_args = reinterpret_cast<handler_args*>(args);
   auto& hosts = h_args->hosts;
   auto& if_mac = h_args->if_mac;
   auto& mtx = *(h_args->mtx);

   // Заполнение структур ether_header и ip 
   const ether_header* eth_header;
   eth_header = reinterpret_cast<const ether_header*>(packet);
   if (ntohs(eth_header->ether_type) != ETHERTYPE_IP){
      spdlog::get("packet_logger")->info("Packet was dropped cause its type is not IP");
      return;
   }
   
   ip* ip_header;
   ip_header = (ip*)(packet + sizeof(ether_header));

   const ether_addr* src_mac = reinterpret_cast<const ether_addr*>(eth_header->ether_shost);
   const ether_addr* dst_mac = reinterpret_cast<const ether_addr*>(eth_header->ether_dhost);

   uint32_t packet_size = header->len;
   std::unique_lock<std::mutex> lock(mtx);
   
   if (std::memcmp(dst_mac, if_mac, sizeof(ether_addr)) == 0){
      // Mac адрес пункта назначения совпадает с mac адресом нашего устройства - значит пакет входящий

      spdlog::get("packet_logger")->info("Packet was marked as incoming");
      
      // Поиск имени хоста на основе его ip адреса
      std::string hostname;
      hostInfo cur_host;
      auto res = cur_host.find_hostname(ip_header, 's');
      if (res != HOSTNAME_DETER_RESULT_TYPE::SUCCEES){
         lock.unlock();
         return;
      }
      
      spdlog::get("packet_logger")->info("Packet source name - {}", cur_host.get_hostname());

      cur_host.make_hostname_pretty();

      // Поиск хоста в общем списке хостов и обновление данных о размере трафика и кол-ве пакетов
      auto it = std::find(hosts->begin(), hosts->end(), cur_host);
      if (it == hosts->end()){
         hosts->push_back(cur_host);
         cur_host.insert_data(packet_size, 'i');
      }
      else{
         (*it).insert_data(packet_size, 'i');
      }
      
   }
   else if (std::memcmp(src_mac, if_mac, sizeof(ether_addr)) == 0){
      // Mac адрес отправителя совпадает с mac адресом нашего устройства - значит пакет исходящий

      spdlog::get("packet_logger")->info("Packet was marked as outgoing");

      // Поиск имени хоста на основе его ip адреса
      std::string hostname;
      hostInfo cur_host;
      auto res = cur_host.find_hostname(ip_header, 'd');
      if (res != HOSTNAME_DETER_RESULT_TYPE::SUCCEES){
         lock.unlock();
         return;
      }

      spdlog::get("packet_logger")->info("Packet destination name - {}", cur_host.get_hostname());

      cur_host.make_hostname_pretty();

      // Поиск хоста в общем списке хостов и обновление данных о размере трафика и кол-ве пакетов
      auto it = std::find(hosts->begin(), hosts->end(), cur_host);
      if (it == hosts->end()){
         cur_host.insert_data(packet_size, 'o');
         hosts->push_back(cur_host);
      }
      else{
         (*it).insert_data(packet_size, 'o');
      }
   }
   else
      spdlog::get("packet_logger")->critical("Unknown package recieved... Skipping");

   lock.unlock();
}