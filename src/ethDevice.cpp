#include "ethDevice.h"

/* Конструктор класса ethDevice. 
 * Он выполняет поиск доступных сетевых интерфейсов с использованием библиотеки pcap, 
 * выбирает первый найденный интерфейс и сохраняет его имя в переменную dev.
*/
ethDevice::ethDevice(){
    spdlog::get("packet_logger")->debug("Find dev func entered");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* interface_list;
	int res = pcap_findalldevs(&interface_list, errbuf);
    if (res == -1){
        spdlog::get("packet_logger")->error("Cannot determine eth device. Exit");
        return;
    }

    dev = std::string(interface_list->name);

    spdlog::get("packet_logger")->debug("Eth dev name - {}", dev);
}

/*
 * Метод класса ethDevice для получения MAC-адреса сетевого интерфейса. 
 * Он использует системные вызовы для получения MAC-адреса интерфейса 
 * на основе его имени dev, сохраненного ранее в объекте. 
 * Полученный MAC-адрес сохраняется в переменную if_mac. 
 */ 

void ethDevice::setup_dev_macAdr(){
    spdlog::get("packet_logger")->debug("Get_dev_macAdr func entered");

    ifreq ifr;
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
   
    std::memcpy(
        &if_mac, 
        reinterpret_cast<ether_addr*>(ifr.ifr_hwaddr.sa_data), 
        sizeof(ether_addr)
    );

    spdlog::get("packet_logger")->info("Get_dev_macAdr func successfully ended");
}

/* Функция setup() выполняет настройку сетевого интерфейса для захвата сетевых пакетов.
 * Она открывает сетевой интерфейс с использованием библиотеки pcap, компилирует и применяет фильтр
 * для захвата только пакетов с портами 80 или 443 (протокол HTTP/HTTPS).
 * Затем вызывает метод setup_dev_macAdr() для получения MAC-адреса сетевого интерфейса.
 * Возвращает результат настройки в виде перечисления SETUP_RESULT_TYPE.
*/ 
SETUP_RESULT_TYPE ethDevice::setup(){
    spdlog::get("packet_logger")->debug("Setup dev func entered");

    char errbuf[PCAP_ERRBUF_SIZE];
    int timeout = 10000;

    handler = pcap_open_live(dev.c_str(), BUFSIZ, 1, timeout, errbuf);
    if (handler == NULL){
        spdlog::get("packet_logger")->error("Cannot compile open eth device. Exit");
        return SETUP_RESULT_TYPE::OPEN_HANDLER_ERROR;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80 or tcp port 443";
    if (pcap_compile(handler, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        spdlog::get("packet_logger")->error("Cannot compile eth filter. Exit");
        return SETUP_RESULT_TYPE::COMPILE_FILTER_ERROR;
    }

    if (pcap_setfilter(handler, &fp) == -1) {
        spdlog::get("packet_logger")->error("Cannot apply eth filter. Exit");
        return SETUP_RESULT_TYPE::APPLY_FILTER_ERROR;
    }

    spdlog::get("packet_logger")->debug("Setup dev func successfully ended");

    setup_dev_macAdr();

    return SETUP_RESULT_TYPE::SUCCESS;
}

// Геттер get_handler() возвращает указатель на обработчик pcap_t, который используется для захвата пакетов.
pcap_t* ethDevice::get_handler(){
    return handler;
}

// Геттер get_if_mac() возвращает MAC-адрес сетевого интерфейса, полученный из метода setup_dev_macAdr().
ether_addr ethDevice::get_if_mac(){
    return if_mac;
}

ethDevice::~ethDevice(){
    if (handler != NULL) {
        pcap_close(handler);
        handler = NULL;
    }
}
