AutoDetect – Abnormal Login Detection System
Introduction

AutoDetect is an anomaly-based login detection system combining AI (Machine Learning) and Rule-Based Detection. It monitors authentication logs, analyzes user behavior, generates alerts, and automatically responds to potential attacks.

This project is suitable for:
Internal IDS/IPS
Enterprise security monitoring systems
SOC / Blue Team operations
Students working on cybersecurity, AI, or smart system projects
Project Structure

Key Features
1. AI Detection (Isolation Forest / Anomaly Detection)

Analyzes login logs

Learns user behavior patterns

Detects anomalies such as:

Login from unusual IP

Login at abnormal hours

Sudden spike in failed logins

Unusual geographic location

2. Rule-Based Detection

Default rules include:

More than 5 failed login attempts in 1 minute

Login from blacklisted countries

User logging in outside working hours

Continuous login attempts in short intervals

3. Monitoring Dashboard (Dashboard.py)

Real-time charts

Alert list

Geographic heatmap

Log viewer

4. Response Engine – Automated Reaction

Block IP addresses

Lock accounts

Send alerts to SOC/Admin

Insert event into SIEM

5. Email Notifications

Sends alerts via SMTP (Gmail or internal mail server)

6. AI Retraining

Automatically updates the model using new data


📘 Report

Full analysis report: AutoDetect_Report.pdf

👤 Author

A student project implementing abnormal login detection using AI + Rule-based logic.

Feel free to ask if you need additional explanations, diagrams, or help with your report! 
