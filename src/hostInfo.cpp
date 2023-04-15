#include "hostInfo.h"

/*
 * Данная функция выполняет преобразование имени хоста, 
 * хранящегося в переменной hostname, в более "красивый" вид. 
 * Она ищет последнее вхождение символа '.' в имени хоста и удаляет все поддомены, 
 * оставляя только последнюю часть после последнего символа '.'. 
 * Если символ '.' не найден, функция возвращается без изменений.
*/
void hostInfo::make_hostname_pretty(){
    size_t ind = hostname.find_last_of('.');
    if (ind == std::string::npos)
        return;
    else{
        size_t ind2 = hostname.substr(0, ind).find_last_of('.');
        if (ind == std::string::npos)
            return;
        else
            hostname = hostname.substr(ind2 + 1, hostname.length());
    }
}

/*
 * Функция определяет имя хоста (hostname) на основе IP-заголовка (ip_header)
 * и определенного значения who, указывающего, является ли хост отправителем ('s')
 * или получателем ('d') в контексте передаваемого IP-пакета.
 * Возвращает результат определения имени хоста в виде значения типа HOSTNAME_DETER_RESULT_TYPE.
 * В случае успешного определения имени хоста, имя хоста сохраняется в переменной класса hostname.
*/ 
HOSTNAME_DETER_RESULT_TYPE hostInfo::find_hostname(const ip* ip_header, char who){
    if (ip_header->ip_v == 4){
        // Случай IPv4, имя хоста определяем при помощи функции gethostbyaddr
        in_addr sender4_ip = (who == 's') ? ip_header->ip_src : ip_header->ip_dst;
        hostent *sender_host = gethostbyaddr(&sender4_ip, sizeof(in_addr), AF_INET);
        if (sender_host == NULL){
            spdlog::get("packet_logger")->warn("Cannot determine hostname(ip: {})... Skipping packet", inet_ntoa(sender4_ip));
            return HOSTNAME_DETER_RESULT_TYPE::IPv4_PROTOCOL_NAME_NOT_FOUND;
        }

        hostname = std::string(sender_host->h_name);
      }
      else if (ip_header->ip_v == 6) {
        // Случай IPv6, для определения имени хоста используется функция getnameinfo
        const ip6_hdr* ip6_header = reinterpret_cast<const ip6_hdr*>(ip_header);
        in6_addr sender6_ip = (who == 's') ? ip6_header->ip6_src : ip6_header->ip6_dst;
         
        char host_str[NI_MAXHOST];
        int ret = getnameinfo(
            reinterpret_cast<sockaddr*>(&sender6_ip), 
            sizeof(sender6_ip), 
            host_str, 
            sizeof(host_str), 
            NULL, 
            0, 
            0
        );
        if (ret != 0){
            spdlog::get("packet_logger")->warn("Cannot determine hostname... Skipping packet");
            return HOSTNAME_DETER_RESULT_TYPE::IPv6_PROTOCOL_NAME_NOT_FOUND;
        }

        hostname = std::string(host_str);
      }

    return HOSTNAME_DETER_RESULT_TYPE::SUCCEES;
}

/*
 * Эта функция предназначена для вставки данных о пакетах в объект hostInfo. 
 * Функция принимает размер пакета (packet_size) в байтах и символ who, 
 * принимающий два значения (i - incoming, o - outgoing). 
 * На основе значения данной переменной, заполняются соответствующиe поля класса.
*/
void hostInfo::insert_data(int packet_size, char who){
    // Приведение байт в килобайты
    double kb_packet_size = packet_size / 1024.0;
         
    if (who == 'i'){ // incoming
        count_in += 1;
        in_package_size += kb_packet_size;
        total_package_size += kb_packet_size;
    }
    else{ // outgoing
        count_out += 1;
        out_package_size += kb_packet_size;
        total_package_size += kb_packet_size;
    }
}

/*
 * Набор функций геттеров для различных полей класса.
*/
std::string hostInfo::get_hostname() const
{
    return hostname;
}

u_int hostInfo::get_count_in() const
{
    return count_in;
}

u_int hostInfo::get_count_out() const
{
    return count_out;
}

double hostInfo::get_in_package_size() const
{
    return in_package_size;
}

double hostInfo::get_out_package_size() const
{
    return out_package_size;
}

double hostInfo::get_total_package_size() const
{
    return total_package_size;
}

/*
 * Оператор сравнения двух экземпляров класс hostInfo.
 * Cравнение производится при помощи сравнения поля hostname.
*/
bool hostInfo::operator==(const hostInfo& host) const
{
    return hostname == host.hostname;
}

void hostInfo::set_hostname(std::string hostname_){
    hostname = hostname_;
}