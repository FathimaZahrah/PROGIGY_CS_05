# Network Packet Sniffer Tool
This project presents a basic packet sniffer tool developed in Python using the Scapy library. The tool captures and analyzes network packets in real-time, providing detailed insights into the communication occurring over a network. When a packet is captured, the tool extracts and displays key information, including the source and destination IP addresses, the protocol used (TCP, UDP, or ICMP), and any available payload data.

# Features

1. Real-time Packet Capture: Continuously listens to network traffic, capturing packets as they traverse the network interface.

2. Protocol Identification: Automatically identifies and categorizes packets based on their protocol type, including:
   * TCP: Transmission Control Protocol

   * UDP: User Datagram Protocol

   * ICMP: Internet Control Message Protocol

   * Additional support for other protocols as needed.

4. Source and Destination Address Display: Extracts and displays the source and destination IP addresses for each captured packet, providing insights into the network communication.

5. Payload Analysis: Offers the ability to inspect the payload data of captured packets if present, allowing for deeper analysis of the transmitted information.

6. Flexible Output: Formats and prints the captured data to the console, making it easy to monitor and understand network activity in real time.

7. Customizable: The code can be easily modified to include additional features or filters, such as limiting captures to specific IP addresses or protocols.

8. Educational Use: Designed for learning and experimentation, helping users understand network protocols and data flow.

9. Ethical Usage Reminder: Promotes ethical usage by ensuring users operate the tool only in authorized environments, adhering to legal and privacy considerations.


# Ethical Considerations
This tool emphasizes ethical usage and should be deployed in environments where the user has permission to monitor network traffic, ensuring compliance with legal and privacy regulations.
