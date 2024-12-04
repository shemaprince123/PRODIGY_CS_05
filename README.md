# PRODIGY_CS_05
---

# Network Packet Analyzer  


This project is a network packet sniffer tool developed to capture and analyze network traffic. It displays essential information such as source and destination IP addresses, protocols, and payload data. **Note:** Use this tool ethically and ensure you have permission to analyze network traffic.

---

## Features  

- **Packet Capture:** Captures network packets in real-time.  
- **Protocol Detection:** Identifies TCP and UDP protocols.  
- **Detailed Analysis:** Displays source and destination IP addresses, protocol type, and payload data (if available).  
- **Customizable Capture Limit:** Easily modify the number of packets captured.  

---

## Requirements  

- Python 3.x  
- `Scapy` library for packet capturing and analysis  

### Installation  
Install the required library using:  
```bash
pip install scapy
```

---

## How to Use  

1. **Run the Script:**  
   Save the code as `packet_analyzer.py`, open a terminal, navigate to the script’s location, and run:  
   ```bash
   sudo python packet_analyzer.py  # Run as admin for network interface access  
   ```

2. **Packet Capture:**  
   The program captures 20 packets by default. Adjust the `count` parameter in the `sniff` function to capture more or fewer packets.

3. **View Packet Details:**  
   For each packet, the tool displays:  
   - **Protocol** (TCP/UDP)  
   - **Source IP Address**  
   - **Destination IP Address**  
   - **Payload Data**  

---

## Screenshots  
![image](https://github.com/user-attachments/assets/848cd444-c1e7-4f7e-be43-e972b0f98886)

### Packet Capture Example:  
*Insert screenshot here*  

### Analyzing Packet Details:  
*Insert screenshot here*  

---

## How It Works  

- **Packet Capture:**  
  The `sniff` function from `Scapy` captures network traffic and passes each packet to the `packet_handler` function.

- **Protocol Detection:**  
  The tool identifies whether a packet belongs to TCP or UDP using `haslayer` checks.

- **Payload Handling:**  
  If a packet contains a raw payload, the tool decodes and displays it. Otherwise, it informs you that no payload data is available.

---

## Ethical Considerations  

- **Use Responsibly:** Ensure you have authorization before monitoring any network traffic. Unauthorized packet sniffing is illegal and unethical.  
- **Educational Purpose:** This tool is designed for learning about network analysis and understanding basic packet structure.  

---

## Disclaimer  

This tool is for educational purposes only. I am not responsible for any misuse of the code.

---
