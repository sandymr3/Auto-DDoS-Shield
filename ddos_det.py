import json
import os
import time
from collections import Counter
import google.generativeai as genai
import dotenv

# === Load environment variables and configure Gemini ===
dotenv.load_dotenv()
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
model = genai.GenerativeModel("gemini-1.5-flash")

# === Suricata eve.json path ===
EVE_PATH = "/var/log/suricata/eve.json"

# === Maintain detected suspicious IPs ===
suspicious_ips = set()

# === Read recent Suricata alerts ===
def read_suricata_alerts(limit=100):
    alerts = []
    try:
        with open(EVE_PATH, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "alert":
                    alerts.append(event)
                if len(alerts) >= limit:
                    break
    except Exception as e:
        print("Error reading Suricata logs:", e)
    return alerts

# === Format alerts for Gemini prompt ===
def format_alerts_for_prompt(alerts):
    prompt = "These are recent Suricata alerts:\n"
    for alert in alerts:
        sig = alert.get('alert', {}).get('signature', 'unknown signature')
        src = alert.get('src_ip', 'N/A')
        dst = alert.get('dest_ip', 'N/A')
        prompt += f"- {sig} from {src} to {dst}\n"
    prompt += "\nDo you suspect a DDoS attack? If so, list the suspicious IPs."
    return prompt

# === Detect IPs with high frequency ===
def detect_ddos_patterns(alerts, threshold=10):
    src_ips = [a.get("src_ip") for a in alerts if a.get("src_ip")]
    ip_counts = Counter(src_ips)
    return {ip: c for ip, c in ip_counts.items() if c > threshold}

# === Update global suspicious IP list ===
def extract_ips_from_ai_response(response_text):
    new_suspects = set()
    lines = response_text.strip().splitlines()
    for line in lines:
        if "." in line:
            ip = line.strip().split()[0]
            new_suspects.add(ip)
    return new_suspects

# === Main detection loop ===
def main():
    print("🚀 DDoS Detection Automation Started...")
    while True:
        alerts = read_suricata_alerts(limit=100)
        if not alerts:
            print("No alerts found. Waiting...")
            time.sleep(15)
            continue

        # Step 1: Pattern-based detection
        high_freq_ips = detect_ddos_patterns(alerts)
        if high_freq_ips:
            print(f"🛑 High traffic detected from IPs: {high_freq_ips}")

        # Step 2: Ask Gemini for validation
        prompt = format_alerts_for_prompt(alerts)
        ai_response = model.generate_content(prompt)
        print("\n🤖 Gemini's Analysis:\n", ai_response.text)

        # Step 3: Update suspected IP list
        new_suspicious = extract_ips_from_ai_response(ai_response.text)
        if new_suspicious:
            suspicious_ips.update(new_suspicious)
            for ip in new_suspicious:
                print(f"⚠️ Simulated block: {ip} [will be auto-blocked in Phase 5]")

        # Wait before next check
        time.sleep(30)

if __name__ == "__main__":
    main()
