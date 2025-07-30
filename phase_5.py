import os
import json
import time
import threading

EVE_LOG = "/var/log/suricata/eve.json"  # Adjust path if needed
BLOCK_DURATION = 900  # 15 minutes (900 seconds)
BLOCKED_IPS = set()

def block_ip(ip):
    if ip in BLOCKED_IPS:
        return
    print(f"[!] Blocking IP: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    BLOCKED_IPS.add(ip)

    def unblock():
        time.sleep(BLOCK_DURATION)
        print(f"[✓] Unblocking IP: {ip}")
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        BLOCKED_IPS.remove(ip)

    threading.Thread(target=unblock).start()

def detect_suspicious_ip(event):
    # Customize this logic based on Suricata rules
    if event.get("event_type") == "alert":
        src_ip = event.get("src_ip")
        alert = event.get("alert", {})
        signature = alert.get("signature", "")

        # DDoS-like keywords can be filtered here
        if "flood" in signature.lower() or "scan" in signature.lower():
            block_ip(src_ip)

def monitor_logs():
    print("[~] Monitoring Suricata logs...")
    with open(EVE_LOG, "r") as f:
        f.seek(0, os.SEEK_END)  # Go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                event = json.loads(line.strip())
                detect_suspicious_ip(event)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\n[!] Stopping agent. All IP blocks will remain until manually removed.")
