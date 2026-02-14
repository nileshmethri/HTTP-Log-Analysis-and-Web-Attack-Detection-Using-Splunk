# HTTP Log Analysis and Web Attack Detection Using Splunk-project

## 📌 Project Overview
This project demonstrates a SOC Analyst L1–level use case for analyzing HTTP logs using Splunk SIEM. The objective is to ingest structured HTTP JSON logs and use SPL (Search Processing Language) queries to detect suspicious web traffic and common web attack patterns such as SQL Injection, XSS, scanning behavior, and abnormal data transfer.

The project focuses on practical log analysis and detection query development aligned with real SOC monitoring tasks.

---

## 🎯 Objectives
- Ingest HTTP JSON logs into Splunk
- Validate field extraction for security analysis
- Analyze web traffic patterns
- Detect common web attack techniques
- Develop reusable SPL detection queries

---

## 🧾 Log Details
**Log Type:** HTTP access logs (JSON format)  
**Fields Used:**  
- timestamp  
- src_ip  
- dest_ip  
- method  
- uri  
- status  
- bytes  
- user_agent  

Logs include both normal and simulated malicious activity for detection practice.

---

## ⚙️ Splunk Ingestion Steps
1. Open Splunk → **Add Data**
2. Upload the HTTP JSON log file
3. Set **Sourcetype = _json**
4. Verify extracted fields in the sidebar
5. Run SPL searches for analysis

---

# 🔍 Detection Queries Implemented

---

## 1️⃣ Top Source IPs — Identify High Traffic / Scanning Hosts
Description:
Shows which source IP addresses generate the most HTTP requests. Useful to quickly spot scanners, bots, or suspicious hosts sending unusually high traffic.
```spl
index=http_lab sourcetype=_json
| stats count by src_ip
| sort -count
```
Screenshot:![Image Alt](https://github.com/nileshmethri/HTTP-Log-Analysis-and-Web-Attack-Detection-Using-Splunk/blob/63cf9f8b4efd36bfbb62d0d0dace8b59bc3a3f79/http-t1.png)

## 2️⃣ SQL Injection Attempt Detection
Description:
Detects possible SQL injection attacks by searching for common SQL keywords and payload patterns inside URL parameters.
```spl
index=http_lab sourcetype=_json
| search uri="*OR 1=1*" OR uri="*UNION*" OR uri="*SELECT*"
| table _time src_ip method uri status user_agent
```
Screenshot:![Image Alt](https://github.com/nileshmethri/HTTP-Log-Analysis-and-Web-Attack-Detection-Using-Splunk/blob/d4cc8df5175b5912a76da44adc7f7c37a7e7bb26/http-t2.png)

## 3️⃣ XSS Attempt Detection
Description:
Finds cross-site scripting attempts where attackers try to inject JavaScript into URL parameters.
```spl
index=http_lab sourcetype=_json
| search uri="*<script>*" OR uri="*alert*"
| table _time src_ip uri status
```
Screenshot:![Image Alt](https://github.com/nileshmethri/HTTP-Log-Analysis-and-Web-Attack-Detection-Using-Splunk/blob/d61aec391f3b67366ddb1b5cf5096abda1565454/http-t3.png)

## 4️⃣ Malicious Tool User-Agent Detection
Description:
Identifies requests coming from known attack or automation tools by analyzing the User-Agent field.
```spl
index=http_lab sourcetype=_json
| search user_agent="*sqlmap*" OR user_agent="*nikto*" OR user_agent="*curl*" OR user_agent="*python*"
| stats count by src_ip user_agent
```
Screenshot:![Image Alt](https://github.com/nileshmethri/HTTP-Log-Analysis-and-Web-Attack-Detection-Using-Splunk/blob/8cdcede761f6aa2b67ea09717097c6d5d04e7bdb/http-t4.png)

## 5️⃣ High Error Code Activity — Scanning / Abuse Indicator
Description:
Shows IPs generating many error responses (401/403/404/500). High error rates often indicate brute force attempts, directory scanning, or malformed attack requests.
```spl
index=http_lab sourcetype=_json status>=400
| stats count by src_ip status
| sort -count
```
Screenshot:![Image Alt]()

## 6️⃣ Large Data Transfer — Possible Exfiltration
Description:
Calculates total data transferred per source IP. Helps detect possible data exfiltration or suspicious large downloads/uploads.
```spl
index=http_lab sourcetype=_json
| stats sum(bytes) as total_bytes by src_ip
| sort -total_bytes
```
Screenshot:![Image Alt]()


