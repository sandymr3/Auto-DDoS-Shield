import json
import os
import google.generativeai as genai
import dotenv
import time

dotenv.load_dotenv()
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))

model = genai.GenerativeModel("gemini-1.5-flash")

# Load eve.json alerts
EVE_PATH = "/var/log/suricata/eve.json"

def read_suricata_alerts(limit=5):
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

# Format for Gemini prompt
def format_alerts_for_prompt(alerts):
    if not alerts:
        return "No recent alerts found in Suricata logs."
    prompt = "These are recent Suricata alerts:\n"
    for alert in alerts:
        prompt += f"- [{alert['timestamp']}] {alert['alert']['signature']}\n"
    prompt += "\nExplain what these alerts mean and if they may indicate a DDoS attack."
    return prompt
from collections import Counter

def detect_ddos_patterns(alerts):
    src_ips = [alert["src_ip"] for alert in alerts if "src_ip" in alert]
    ip_counts = Counter(src_ips)

    frequent_ips = {ip: count for ip, count in ip_counts.items() if count > 10}
    if frequent_ips:
        return f"Possible DDoS: High frequency from IPs: {frequent_ips}"
    else:
        return "No strong DDoS patterns found."
    


while True:
    alerts = read_suricata_alerts(limit=100)
    summary = detect_ddos_patterns(alerts)
    
    # Optional: Ask Gemini for deeper explanation
    full_prompt = f"The following is alert summary:\n{summary}\n\nExplain it simply."
    ai_response = model.generate_content(full_prompt)
    print(ai_response.text)
    
    if "DDoS" in summary:
        print("⚠️ Action: Blocking suspected IPs... [Simulated]")

    time.sleep(30)  # wait before next check

