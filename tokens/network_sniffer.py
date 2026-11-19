import threading
import time
import sys
import os
import socket

PLATFORM = sys.platform  # "win32" or "linux"


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
        self.known_dns_entries = self.get_dns_cache()
        self.thread = threading.Thread(target=self.dns_monitor_loop, daemon=True)
        self.thread.start()
        self.logger.log(
            "NETWORK",
            f"DNS & Web Monitor Started (Baseline: {len(self.known_dns_entries)} active domains)"
        )

    def stop(self):
        self.running = False

    # ─────────────────────────────────────────────────────────────────────────
    # Platform dispatcher
    # ─────────────────────────────────────────────────────────────────────────
    def get_dns_cache(self):
        if PLATFORM == "win32":
            return self._get_dns_cache_windows()
        elif PLATFORM == "linux":
            return self._get_dns_cache_linux()
        return set()

    # ─────────────────────────────────────────────────────────────────────────
    # Windows — original DnsGetCacheDataTable via ctypes
    # ─────────────────────────────────────────────────────────────────────────
    def _get_dns_cache_windows(self):
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

    # ─────────────────────────────────────────────────────────────────────────
    # Linux — multi-source DNS monitoring
    # ─────────────────────────────────────────────────────────────────────────
    def _get_dns_cache_linux(self):
        """
        Linux has no single DNS-cache API like Windows.
        We combine three non-root approaches:
          1. Reverse-DNS on ESTABLISHED TCP connections from /proc/net/tcp & tcp6
          2. Parse systemd-resolved journal via journalctl
          3. Read /run/systemd/resolve/resolv.conf to know the resolver
        """
        entries = set()
        entries.update(self._proc_net_reverse_dns())
        entries.update(self._journalctl_dns())
        return entries

    def _proc_net_reverse_dns(self):
        """
        Read /proc/net/tcp (and tcp6) for ESTABLISHED connections on
        ports 80/443/53, then reverse-DNS the remote IP to get domain names.
        """
        domains = set()
        for proc_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            if not os.path.exists(proc_file):
                continue
            try:
                with open(proc_file) as f:
                    lines = f.readlines()[1:]          # skip header
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    remote_hex = parts[2]
                    state      = parts[3]
                    if state != "01":                  # only ESTABLISHED
                        continue
                    if ":" not in remote_hex:
                        continue
                    ip_hex, port_hex = remote_hex.rsplit(":", 1)
                    port = int(port_hex, 16)
                    if port not in (80, 443, 53):
                        continue
                    try:
                        if len(ip_hex) == 8:           # IPv4 (little-endian)
                            ip_bytes = bytes.fromhex(ip_hex)[::-1]
                            ip_str   = socket.inet_ntop(socket.AF_INET, ip_bytes)
                            hostname = socket.gethostbyaddr(ip_str)[0]
                            domains.add(hostname.lower())
                    except Exception:
                        pass
            except Exception:
                pass
        return domains

    def _journalctl_dns(self):
        """
        Parse DNS queries logged by systemd-resolved in the system journal.
        Requires systemd-resolved to be active (default on Ubuntu 18.04+).
        """
        import subprocess
        domains = set()
        try:
            result = subprocess.run(
                [
                    "journalctl", "-u", "systemd-resolved",
                    "--since", "30 seconds ago",
                    "--no-pager", "-o", "short", "-q"
                ],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                # Lines look like: "Using DNS server ... for domain ..."
                # or "DNSSEC ... <domain>"
                if "DNSSEC" in line or "Sending" in line or "Resolved" in line:
                    for token in line.split():
                        # Basic heuristic: looks like a domain name
                        if "." in token and len(token) > 4 and not token.startswith("["):
                            clean = token.strip(".,;:'\"").lower()
                            if clean and not clean.startswith("-"):
                                domains.add(clean)
        except Exception:
            pass
        return domains

    # ─────────────────────────────────────────────────────────────────────────
    # Monitoring loop (identical for both platforms)
    # ─────────────────────────────────────────────────────────────────────────
    def dns_monitor_loop(self):
        while self.running:
            try:
                current_entries = self.get_dns_cache()
                new_entries     = current_entries - self.known_dns_entries

                for domain in new_entries:
                    domain_lower = domain.lower()
                    matched = next(
                        (k for k in self.suspicious_domains if k in domain_lower), None
                    )
                    if matched:
                        self.logger.log(
                            "ALERT",
                            f"Prohibited AI / Website Access Detected (DNS): {domain}",
                            is_suspicious=True
                        )
                    else:
                        # Skip purely local / mDNS / reverse-lookup noise
                        if (not domain_lower.endswith('.local') and
                                not domain_lower.endswith('.arpa') and
                                not domain_lower.startswith('_')):
                            self.logger.log("URL", f"Network Domain Query: {domain}")

                self.known_dns_entries = current_entries
            except Exception:
                pass

            time.sleep(1)
