# Network Security Scanner

A comprehensive network vulnerability scanner with GUI, built in Python.  
Detects open/closed ports, services, devices, and potential security issues in your network.

---

# Network Security Scanner (EN)

A simple and practical network security scanner in Python with a user-friendly interface.

## How does it work?

1. **Port scanning**
   - Scans a given IP address for open, closed, and filtered ports (range configurable).
   - Detects running services and their versions using Nmap.
   - Optionally shows closed ports.

2. **Device discovery**
   - Finds all devices in a given network range using ARP requests (Scapy).
   - Displays IP and MAC addresses of detected devices.

3. **Vulnerability analysis**
   - Checks for common vulnerabilities based on open ports and detected services.
   - Optionally queries public CVE databases for known issues.

4. **ARP spoofing detection**
   - Alerts if duplicate MAC addresses are detected in the network.

5. **Result logging**
   - Saves scan results to a timestamped CSV file.
   - Logs all actions for auditing.

6. **User interface**
   - Simple GUI (Tkinter) with fields for IP, network range, port range, alert level, and a checkbox for closed ports.

## Requirements

- Python 3.8+
- `python-nmap`
- `scapy`
- Nmap installed and added to PATH

## Security recommendations

- Use only on networks you are authorized to scan.
- Do not scan public IPs without permission.
- Regularly review logs and backup your results.
- This project is for educational and portfolio purposes.

---

**This project demonstrates practical network security and vulnerability assessment skills.**

---

# Network Security Scanner (PL)

Prosty i praktyczny skaner bezpieczeństwa sieci z graficznym interfejsem, napisany w Pythonie.

## Jak to działa?

1. **Skanowanie portów**
   - Skanuje wskazany adres IP pod kątem otwartych, zamkniętych i filtrowanych portów (zakres konfigurowalny).
   - Wykrywa uruchomione usługi i ich wersje (Nmap).
   - Opcjonalnie pokazuje zamknięte porty.

2. **Wykrywanie urządzeń**
   - Wyszukuje wszystkie urządzenia w podanym zakresie sieci (ARP, Scapy).
   - Wyświetla adresy IP i MAC wykrytych urządzeń.

3. **Analiza podatności**
   - Sprawdza typowe podatności na podstawie otwartych portów i usług.
   - Opcjonalnie pobiera znane podatności z publicznych baz CVE.

4. **Wykrywanie ARP spoofingu**
   - Ostrzega, jeśli w sieci wykryto duplikaty adresów MAC.

5. **Logowanie wyników**
   - Zapisuje wyniki skanowania do pliku CSV z datą.
   - Loguje wszystkie działania do pliku tekstowego.

6. **Interfejs użytkownika**
   - Prosty GUI (Tkinter) z polami na IP, zakres sieci, zakres portów, poziom alertów i opcją pokazywania zamkniętych portów.

## Wymagania

- Python 3.8+
- `python-nmap`
- `scapy`
- Zainstalowany Nmap (dodany do PATH)

## Zalecenia bezpieczeństwa

- Używaj tylko w sieciach, do których masz uprawnienia.
- Nie skanuj publicznych adresów IP bez zgody.
- Regularnie przeglądaj logi i rób kopie zapasowe wyników.
- Projekt do celów edukacyjnych i portfolio.

---

**Projekt pokazuje praktyczne umiejętności z zakresu bezpieczeństwa i analizy sieci.**

---
