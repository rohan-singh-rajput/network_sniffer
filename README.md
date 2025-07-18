# Network Sniffer & Visualizer (C++ + Flask)

A lightweight, real-time network packet sniffer and web-based visualizer built using C++ (`libpcap`) and Python (`Flask`).

---

## Features

###  Packet Sniffer (`sniffer_pcap.cpp`)
- Cross-platform packet capture using `libpcap` (Linux/macOS)
- Supports TCP, UDP, ICMP, and other IP protocols
- Parses and logs:
  - Source & destination IPs
  - Source & destination ports (for TCP/UDP)
  - Protocol types
- Appends each packet to `packets.json` in newline-delimited JSON (NDJSON) format
- Easily filter packets by protocol using the `filter_protocol` variable

###  Web Visualizer (Flask App)
- `/packets`: Returns the last 100 packets from `packets.json`
- `/stats`: Returns protocol distribution (TCP, UDP, ICMP, OTHER)
- `/`: Serves `index.html` (live view UI)
- `/getstats`: Serves `stats.html` (protocol graph)

###  Visualization
- Easily connect HTML/JS frontend using AJAX (e.g., fetch `/packets` every 5s)
- Add Chart.js to plot stats from `/stats`

