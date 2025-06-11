import nmap, scapy.all as scapy, csv, os, datetime, sys, re, requests
from tkinter import Tk, Label, Entry, Button, Text, messagebox, Checkbutton, IntVar, Frame
from tkinter import ttk

VULNERABILITY_DB = {
    21: "FTP – podatny na brute-force, przesyła dane w postaci jawnej.",
    22: "SSH – podatny na brute-force, możliwe słabe hasła.",
    23: "Telnet – podatny na brute-force.",
    25: "SMTP – możliwy open relay, podatny na spam.",
    53: "DNS – podatny na ataki typu DNS amplification.",
    80: "HTTP – możliwy XSS/SQL Injection.",
    110: "POP3 – przesyła hasła w postaci jawnej.",
    139: "NetBIOS – podatny na ataki enumeracyjne.",
    143: "IMAP – przesyła hasła w postaci jawnej.",
    445: "SMB – podatny na WannaCry.",
    3389: "RDP – podatny na brute-force, podatności RDP.",
    3306: "MySQL – podatny na brute-force, podatności SQL.",
    5432: "PostgreSQL – podatny na brute-force.",
    5900: "VNC – podatny na brute-force, przesyła dane jawnie."
}
CONFIG = {"port_range": "1-1024", "alert_level": "high"}

def log_action(msg):
    with open("scan_log.txt", 'a', encoding='utf-8') as f:
        f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")

def is_valid_ip(ip): return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is not None
def is_valid_port_range(port_range): return re.match(r"^\d{1,5}-\d{1,5}$", port_range) is not None

def scan_ports(target, show_closed):
    scanner = nmap.PortScanner()
    scanner.scan(target, CONFIG["port_range"], arguments='-sV')
    ports = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'unknown')
                version = scanner[host][proto][port].get('version', '')
                if state == 'open' or show_closed:
                    ports.append([host, port, state, proto, service, version])
                if state == 'open':
                    log_action(f"Port {port} na {host} otwarty, usługa: {service}, wersja: {version}")
    return ports

def detect_devices(network):
    arp = scapy.ARP(pdst=network)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = scapy.srp(ether/arp, timeout=2, verbose=False)[0]
    devices = [[sent.psrc, sent.hwsrc] for sent, _ in answered]
    for ip, mac in devices: log_action(f"Urządzenie: {ip}, MAC {mac}")
    return devices

def detect_arp_spoofing(devices):
    macs, alerts = {}, []
    for ip, mac in devices:
        if mac in macs and macs[mac] != ip:
            alerts.append(f"Możliwy ARP spoofing: MAC {mac} przypisany do {macs[mac]} i {ip}")
        macs[mac] = ip
    return alerts

def check_cve(service, version):
    if not service or not version: return []
    try:
        url = f"https://cve.circl.lu/api/search/{service}/{version}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return [item['id'] for item in data.get('results', [])][:3]
    except Exception as e:
        log_action(f"Błąd pobierania CVE: {e}")
    return []

def check_vulnerabilities(ports):
    vulns = []
    for host, port, state, proto, service, version in ports:
        if port in VULNERABILITY_DB and CONFIG["alert_level"] == "high" and state == "open":
            msg = f"Ryzyko na {host}, port {port}: {VULNERABILITY_DB[port]} (usługa: {service}, wersja: {version})"
            log_action(msg)
            vulns.append(msg)
        cves = check_cve(service, version) if state == "open" else []
        if cves:
            cve_msg = f"CVE dla {service} {version} na {host}:{port}: {', '.join(cves)}"
            log_action(cve_msg)
            vulns.append(cve_msg)
    return vulns

def save_to_csv(ports, devices, vulns, arp_alerts):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"scan_results_{ts}.csv", 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["Host", "Port", "State", "Protocol", "Service", "Version"])
        w.writerows(ports)
        if vulns:
            w.writerow(["Issues"])
            w.writerows([[v] for v in vulns])
        if arp_alerts:
            w.writerow(["ARP Alerts"])
            w.writerows([[a] for a in arp_alerts])
        w.writerow(["IP", "MAC"])
        w.writerows(devices)
    log_action(f"Zapisano do scan_results_{ts}.csv")

def run_scan(target, network, show_closed):
    ports = scan_ports(target, show_closed)
    devices = detect_devices(network)
    arp_alerts = detect_arp_spoofing(devices)
    vulns = check_vulnerabilities(ports)
    save_to_csv(ports, devices, vulns, arp_alerts)
    return ports, devices, vulns, arp_alerts

def start_scan(target, network, port_range, alert_level, show_closed, result_text):
    if not is_valid_ip(target):
        messagebox.showerror("Błąd", "Niepoprawny adres IP!")
        return
    if not is_valid_port_range(port_range):
        messagebox.showerror("Błąd", "Niepoprawny zakres portów!")
        return
    CONFIG["port_range"] = port_range
    CONFIG["alert_level"] = alert_level
    result_text.delete(1.0, "end")
    ports, devices, vulns, arp_alerts = run_scan(target, network, show_closed)
    result_text.insert("end", f"Porty (zakres: {CONFIG['port_range']}):\n")
    for p in ports:
        result_text.insert("end", f"{p[0]}, {p[1]}, {p[2]}, {p[3]}, {p[4]}, {p[5]}\n")
    result_text.insert("end", "\nUrządzenia:\n")
    for d in devices:
        result_text.insert("end", f"{d[0]}, {d[1]}\n")
    if vulns:
        result_text.insert("end", "\nProblemy:\n")
        for v in vulns:
            result_text.insert("end", f"{v}\n")
    if arp_alerts:
        result_text.insert("end", "\nAlerty ARP:\n")
        for a in arp_alerts:
            result_text.insert("end", f"{a}\n")
    result_text.insert("end", "\nZapisano do CSV!")

def gui():
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                messagebox.showerror("Błąd", "Uruchom jako admin!")
                sys.exit(1)
        except: pass

    root = Tk()
    root.title("Network Scanner")
    root.geometry("540x650")
    root.configure(bg="#f0f0f0")

    Label(root, text="IP do skanowania:", bg="#f0f0f0").pack(pady=(15, 0))
    target = Entry(root, width=30)
    target.insert(0, "192.168.1.1")  # Zmieniony na przykładowy adres
    target.pack(pady=5)

    Label(root, text="Zakres sieci:", bg="#f0f0f0").pack(pady=(10, 0))
    network = Entry(root, width=30)
    network.insert(0, "192.168.1.0/24")  # Zmieniony na przykładowy zakres
    network.pack(pady=5)

    Label(root, text="Zakres portów:", bg="#f0f0f0").pack(pady=(10, 0))
    port_range = Entry(root, width=30)
    port_range.insert(0, CONFIG["port_range"])
    port_range.pack(pady=5)

    Label(root, text="Poziom alertów (high/low):", bg="#f0f0f0").pack(pady=(10, 0))
    alert_level = ttk.Combobox(root, values=["high", "low"], width=27, state="readonly")
    alert_level.set(CONFIG["alert_level"])
    alert_level.pack(pady=5)

    show_closed = IntVar()
    Checkbutton(root, text="Pokazuj zamknięte porty", variable=show_closed, bg="#f0f0f0").pack(pady=(5, 0))

    result = Text(root, height=18, width=60, bg="white", fg="black")
    result.pack(pady=10, padx=10)

    btn_frame = Frame(root, bg="#f0f0f0")
    btn_frame.pack(fill="x")
    Button(btn_frame, text="Skanuj", command=lambda: start_scan(
        target.get(), network.get(), port_range.get(), alert_level.get(), show_closed.get(), result
    ), bg="#4CAF50", fg="white", padx=15).pack(pady=(5, 15))

    root.mainloop()

if __name__ == "__main__":
    gui()