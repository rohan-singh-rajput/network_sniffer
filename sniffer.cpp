// sniffer_pcap.cpp - Cross-platform Packet Sniffer using libpcap (works on
// macOS/Linux)
#include "json.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

using json = nlohmann::json;

std::ofstream logfile("packets.json", std::ios::app); // append mode
int filter_protocol = 0; // change to IPPROTO_UDP, IPPROTO_ICMP or 0 for all

void log_json(const std::string &proto, const std::string &src,
              const std::string &dst, int sport, int dport) {
  json j;
  j["protocol"] = proto;
  j["source"] = src;
  j["destination"] = dst;
  if (sport >= 0)
    j["src_port"] = sport;
  if (dport >= 0)
    j["dst_port"] = dport;
  logfile << j.dump() << "\n";
  logfile.flush();
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  struct ip *iph = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
  int ip_header_len = iph->ip_hl * 4;

  std::string src_ip = inet_ntoa(iph->ip_src);
  std::string dst_ip = inet_ntoa(iph->ip_dst);

  if (filter_protocol != 0 && iph->ip_p != filter_protocol)
    return;

  switch (iph->ip_p) {
  case IPPROTO_TCP: {
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ip_header_len);
    int sport = ntohs(tcph->th_sport);
    int dport = ntohs(tcph->th_dport);
    std::cout << "[TCP] " << src_ip << ":" << sport << " -> " << dst_ip << ":"
              << dport << "\n";
    log_json("TCP", src_ip, dst_ip, sport, dport);
    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udph = (struct udphdr *)(packet + 14 + ip_header_len);
    int sport = ntohs(udph->uh_sport);
    int dport = ntohs(udph->uh_dport);
    std::cout << "[UDP] " << src_ip << ":" << sport << " -> " << dst_ip << ":"
              << dport << "\n";
    log_json("UDP", src_ip, dst_ip, sport, dport);
    break;
  }
  case IPPROTO_ICMP: {
    std::cout << "[ICMP] " << src_ip << " -> " << dst_ip << "\n";
    log_json("ICMP", src_ip, dst_ip, -1, -1);
    break;
  }
  default:
    std::cout << "[OTHER] " << src_ip << " -> " << dst_ip
              << " | Protocol: " << int(iph->ip_p) << "\n";
    log_json("OTHER", src_ip, dst_ip, -1, -1);
    break;
  }
}

int main() {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Print all devices
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    std::cerr << "Error finding devices: " << errbuf << "\n";
    return 1;
  }
  std::cout << "Available interfaces:\n";
  for (pcap_if_t *d = alldevs; d; d = d->next) {
    std::cout << " - " << d->name << "\n";
  }

  // Set interface manually (e.g., en0 for Wi-Fi on macOS)
  const char *dev = "en0";
  std::cout << "\nSniffing on device: " << dev << "\n";

  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (!handle) {
    std::cerr << "pcap_open_live() failed: " << errbuf << "\n";
    return 1;
  }

  pcap_loop(handle, 0, packet_handler, nullptr);

  pcap_close(handle);
  pcap_freealldevs(alldevs);
  logfile.close();
  return 0;
}