# ESP-IDF project: dual-band Wi-Fi sniffer that streams a live PCAP to Wireshark over USB
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32c5_sniffer)
