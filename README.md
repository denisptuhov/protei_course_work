## Traffic sniffer
This project provides a terminal tool for traffic sniffering based on libpcap
### Dependencies
For logging in this project, the [spdlog](https://github.com/gabime/spdlog) library is used

Spdlog requires the [fmt](https://github.com/fmtlib/fmt) library to work correctly

For packet capture in this project, the [libpcap](https://www.tcpdump.org/) library is used

Make sure that following libs are installed on your system:
```
sudo apt install libspdlog-dev
sudo apt install libfmt-dev
sudo apt install libpcap-dev
```

For testing in this project, the [gtest](https://github.com/google/googletest) library is used
```
sudo apt-get install libgtest-dev
```


### Install
```
git clone https://github.com/denisptuhov/protei_course_work
cd protei_course_work && mkdir build && cd build
cmake .. && make
```
### Run
`./traffic_sniffer` - to run sniffer

`./sniffer_tests` - to run tests

### About
This program works endlessly, printing hosts info every 5 seconds.

To exit press Ctrl+C
