import requests
import pandas as pd
import matplotlib.pyplot as plt
import json
import time

VULNERS_API_KEY = ""
VT_API_KEY = ""

suspicious_ips = [
    "45.33.32.156",
    "185.220.101.1",
    "23.129.64.130",
    "171.25.193.9",
    "192.42.116.16"
]


def get_vulnerabilities():
    url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        "X-Api-Key": VULNERS_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "query": "cvss.score:[7 TO 10] order:published",
        "size": 10,
        "fields": ["id", "title", "cvss", "published"]
    }
    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        print(f"Ошибка Vulners API: HTTP {response.status_code}")
        print(response.text[:500])
        return []

    data = response.json()

    if data.get("result") != "OK":
        print(f"Vulners вернул ошибку: {data.get('data', {}).get('error', 'неизвестная')}")
        return []

    result = []
    for item in data.get("data", {}).get("search", []):
        source = item.get("_source", {})
        cvss = source.get("cvss", {})
        if type(cvss) is dict:
            score = cvss.get("score", 0)
        else:
            score = 0
        vuln = {
            "id": source.get("id", "N/A"),
            "cvss_score": score,
            "title": source.get("title", "N/A"),
            "published": source.get("published", "N/A")
        }
        result.append(vuln)
    return result


def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 429:
        print(f"  Лимит VirusTotal, жду 60 секунд...")
        time.sleep(60)
        response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"  Ошибка VT для {ip}: HTTP {response.status_code}")
        return {
            "ip": ip, "country": "N/A",
            "malicious": 0, "suspicious": 0, "harmless": 0
        }

    data = response.json()
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "country": attrs.get("country", "N/A"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }


def respond_to_threat(item, threat_type):
    if threat_type == "vuln" and item["cvss_score"] >= 9:
        print(f"[CRITICAL] Уязвимость {item['id']} (CVSS {item['cvss_score']}) — требуется немедленное обновление!")
    elif threat_type == "vuln" and item["cvss_score"] >= 7:
        print(f"[WARNING] Уязвимость {item['id']} (CVSS {item['cvss_score']}) — рекомендуется обновление")

    if threat_type == "ip" and item["malicious"] > 5:
        print(f"[BLOCKED] IP {item['ip']} заблокирован — {item['malicious']} детектов malicious")
    elif threat_type == "ip" and item["suspicious"] > 3:
        print(f"[ALERT] IP {item['ip']} подозрительный — {item['suspicious']} детектов suspicious")


print("=" * 50)
print("Сбор данных об уязвимостях из Vulners API")
print("=" * 50)
vulns = get_vulnerabilities()
print(f"Получено уязвимостей: {len(vulns)}")
for v in vulns:
    print(f"  {v['id']} — CVSS {v['cvss_score']}")

print()
print("=" * 50)
print("Проверка подозрительных IP через VirusTotal API")
print("=" * 50)
ip_results = []
for ip in suspicious_ips:
    result = check_ip(ip)
    ip_results.append(result)
    print(f"  {ip}: malicious={result['malicious']}, suspicious={result['suspicious']}, country={result['country']}")
    time.sleep(15)

print()
print("=" * 50)
print("Реагирование на угрозы")
print("=" * 50)
for v in vulns:
    respond_to_threat(v, "vuln")
for ip_res in ip_results:
    respond_to_threat(ip_res, "ip")

report = {
    "vulnerabilities": vulns,
    "ip_analysis": ip_results,
    "blocked_ips": [r["ip"] for r in ip_results if r["malicious"] > 5],
    "critical_vulns": [v["id"] for v in vulns if v["cvss_score"] >= 9]
}

with open("report.json", "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
print("\nОтчёт сохранён: report.json")

df_vulns = pd.DataFrame(vulns)
df_ips = pd.DataFrame(ip_results)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))

if not df_vulns.empty:
    df_vulns_sorted = df_vulns.sort_values("cvss_score", ascending=True)
    colors = []
    for score in df_vulns_sorted["cvss_score"]:
        if score >= 9:
            colors.append("red")
        elif score >= 7:
            colors.append("orange")
        else:
            colors.append("gray")
    axes[0].barh(df_vulns_sorted["id"], df_vulns_sorted["cvss_score"], color=colors)
    axes[0].set_xlabel("CVSS Score")
    axes[0].set_title("Уязвимости по CVSS")
    axes[0].axvline(x=9, color="red", linestyle="--", alpha=0.5)
    axes[0].axvline(x=7, color="orange", linestyle="--", alpha=0.5)

if not df_ips.empty:
    axes[1].bar(df_ips["ip"], df_ips["malicious"], color="tomato", label="Malicious")
    axes[1].bar(df_ips["ip"], df_ips["suspicious"], bottom=df_ips["malicious"], color="gold", label="Suspicious")
    axes[1].set_ylabel("Detections")
    axes[1].set_title("Анализ IP-адресов")
    axes[1].legend()
    axes[1].tick_params(axis="x", rotation=45)

plt.tight_layout()
plt.savefig("chart.png", dpi=150)
print("График сохранён: chart.png")
