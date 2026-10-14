import socket
import struct
import threading
import time
import os
import ctypes
from ctypes import wintypes

class DNS_CACHE_ENTRY(ctypes.Structure):
    pass

DNS_CACHE_ENTRY._fields_ = [
    ('pNext', ctypes.POINTER(DNS_CACHE_ENTRY)),
    ('recName', wintypes.LPWSTR),
    ('wType', wintypes.WORD),
    ('wDataLength', wintypes.WORD),
    ('dwFlags', wintypes.DWORD)
]

class NetworkSniffer:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_dns_entries = set()
        self.suspicious_domains = [
            "openai", "chatgpt", "oaistatic", "claude", "anthropic",
            "gemini", "bard.google", "perplexity", "deepseek", "chegg",
            "stackoverflow", "stackexchange", "quora", "brainly", "blackbox",
            "copilot.microsoft", "github.com/copilot", "chat.deepseek",
            "huggingface.co", "poe.com", "phind.com"
        ]

    def start(self):
        self.running = True
        # Populate initial DNS cache baseline so past visits before exam aren't falsely triggered
        self.known_dns_entries = self.get_dns_cache()
        self.thread = threading.Thread(target=self.dns_monitor_loop, daemon=True)
        self.thread.start()
        self.logger.log("NETWORK", f"DNS & Web Monitor Started (Baseline: {len(self.known_dns_entries)} active domains)")

    def get_dns_cache(self):
        """Fetches active domains from Windows DNS Client Resolver Cache (requires no Admin rights)."""
        entries = set()
        try:
            dnsapi = ctypes.windll.dnsapi
            DnsGetCacheDataTable = dnsapi.DnsGetCacheDataTable
            DnsGetCacheDataTable.restype = wintypes.BOOL
            DnsGetCacheDataTable.argtypes = [ctypes.POINTER(ctypes.POINTER(DNS_CACHE_ENTRY))]

            pEntry = ctypes.POINTER(DNS_CACHE_ENTRY)()
            if DnsGetCacheDataTable(ctypes.byref(pEntry)):
                curr = pEntry
                while curr:
                    name = curr.contents.recName
                    if name:
                        entries.add(name.lower().strip())
                    curr = curr.contents.pNext
        except Exception:
            pass
        return entries

    def dns_monitor_loop(self):
        """Continuously checks for newly resolved domains during the exam."""
        while self.running:
            try:
                current_entries = self.get_dns_cache()
                new_entries = current_entries - self.known_dns_entries

                for domain in new_entries:
                    domain_lower = domain.lower()
                    # Check against prohibited keywords
                    matched = next((k for k in self.suspicious_domains if k in domain_lower), None)
                    if matched:
                        self.logger.log(
                            "ALERT",
                            f"Prohibited AI / Website Access Detected (DNS): {domain}",
                            is_suspicious=True
                        )
                    else:
                        # Log high-level web activity
                        if not domain_lower.endswith('.local') and not domain_lower.endswith('.arpa') and not domain_lower.startswith('_'):
                            self.logger.log("URL", f"Network Domain Query: {domain}")

                self.known_dns_entries = current_entries
            except Exception:
                pass

            time.sleep(1)

    def stop(self):
        self.running = False
