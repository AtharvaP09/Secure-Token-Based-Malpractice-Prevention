import socket
import struct
import threading
import time
import os

class NetworkSniffer:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.host = socket.gethostbyname(socket.gethostname())
        self.sniffer = None
        self.thread = None

    def start(self):
        self.running = True
        # Try raw socket sniffing
        try:
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sniffer.bind((self.host, 0))
            self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Windows specific IOCTL
            try:
                self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except AttributeError:
                self.logger.log("ERROR", "Raw sockets not supported (Non-Windows?)")
                return

            self.thread = threading.Thread(target=self.sniff_loop)
            self.thread.start()
            self.logger.log("NETWORK", "Raw Socket Sniffer Started")
        except Exception as e:
            self.logger.log("ERROR", f"Failed to start raw sniffer: {e} - Run as Admin?")
            self.running = False

    def sniff_loop(self):
        while self.running:
            try:
                if self.sniffer:
                    raw_data, addr = self.sniffer.recvfrom(65535)
                    # Parse IP packet
                    ip_header = raw_data[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    iph_length = ihl * 4
                    
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    if protocol == 6: # TCP
                        self.handle_tcp(raw_data[iph_length:], s_addr, d_addr)
                    elif protocol == 17: # UDP
                        self.handle_udp(raw_data[iph_length:], s_addr, d_addr)
            except Exception:
                continue

    def handle_tcp(self, packet, src, dst):
        # Extract Destination Port and Payload (Try to find HTTP Host or TLS SNI)
        # Simplified parsing
        try:
            tcph = struct.unpack('!HHLLBBHHH', packet[:20])
            dest_port = tcph[1]
            data = packet[tcph[4]*4:] # Offset
            
            if dest_port == 80 and len(data) > 0:
                # HTTP Host
                try:
                    text = data.decode('utf-8', errors='ignore')
                    if "Host:" in text:
                        host = text.split("Host: ")[1].split("\r\n")[0]
                        
                        suspicious_domains = ["openai.com", "chatgpt.com", "claude.ai", "stackoverflow.com", "chegg.com", "quora.com", "bard.google.com"]
                        is_suspicious = any(d in host for d in suspicious_domains)
                        
                        if is_suspicious:
                            self.logger.log("ALERT", f"Suspicious Website Visit: {host}", is_suspicious=True)
                        else:
                            self.logger.log("WEB", f"HTTP Visit: {host}")
                except:
                    pass
            elif dest_port == 443 and len(data) > 0:
                pass
        except:
            pass

    def handle_udp(self, packet, src, dst):
        # UDP - Check for DNS (Port 53)
        try:
            udph = struct.unpack('!HHHH', packet[:8])
            dest_port = udph[1]
            data = packet[8:]
            
            if dest_port == 53:
                # DNS Query
                # Parse DNS header/question to get domain
                # Simplistic string search for domains in the payload
                try:
                     payload_text = data.decode('utf-8', errors='ignore')
                     # Remove non-printable to make it easier
                     clean_text = "".join([c if c.isprintable() else '.' for c in payload_text])
                     
                     suspicious_domains = ["openai", "chatgpt", "claude", "stackoverflow", "chegg", "quora", "bard"]
                     
                     for domain in suspicious_domains:
                         if domain in clean_text:
                              self.logger.log("ALERT", f"Suspicious DNS Query: {domain}", is_suspicious=True)
                              return

                     self.logger.log("DNS", f"DNS Query detected")
                except:
                     pass
        except:
            pass

    def stop(self):
        self.running = False
        try:
            self.sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sniffer.close()
        except:
            pass
