\# Hybrid Network Security Monitoring and Intrusion Detection System



\## Project Title



Hybrid Network Security Monitoring and Intrusion Detection System using Rule-Based and Machine Learning Detection with Adaptive Risk Scoring



\---



\## Project Description



This project is a Network Security Monitoring and Intrusion Detection System designed to monitor network traffic, extract packet information, detect suspicious network activity, generate security alerts, and store detected events for further analysis.



The system combines rule-based detection techniques with machine learning-based detection and adaptive risk scoring to improve the identification and prioritization of suspicious network behavior.



\---



\## Objectives



\- Capture network packets in real time.

\- Extract useful information from network packets.

\- Monitor network traffic statistics.

\- Detect suspicious network behavior.

\- Detect possible port scanning activity.

\- Detect possible packet flooding activity.

\- Detect possible ICMP flooding activity.

\- Generate security alerts.

\- Store security alerts in an SQLite database.

\- Apply machine learning for network traffic classification.

\- Develop adaptive risk scoring.

\- Provide an explainable security monitoring dashboard.



\---



\## System Architecture



```text

NETWORK TRAFFIC

&#x20;     |

&#x20;     v

Packet Capture

&#x20;   (Scapy)

&#x20;     |

&#x20;     v

Packet Parser

&#x20;     |

&#x20;     v

Feature Extraction

&#x20;     |

&#x20;     +----------------------+

&#x20;     |                      |

&#x20;     v                      v

Rule-Based IDS          ML-Based IDS

&#x20;     |                      |

&#x20;     +----------+-----------+

&#x20;                |

&#x20;                v

&#x20;       Adaptive Risk Scoring

&#x20;                |

&#x20;                v

&#x20;         Alert Manager

&#x20;                |

&#x20;                v

&#x20;           SQLite DB

&#x20;                |

&#x20;                v

&#x20;         Web Dashboard







Technologies Used

Python

Scapy

SQLite

Machine Learning

Scikit-learn

Pandas

NumPy

Streamlit

Git

GitHub

Current Project Status

Completed

&#x20;Project structure created

&#x20;Python environment configured

&#x20;Scapy installed

&#x20;Npcap configured for Windows packet capture

&#x20;Real-time packet capture

&#x20;Packet parsing

&#x20;Network statistics

&#x20;Port scan detection

&#x20;General flood detection

&#x20;ICMP flood detection

&#x20;SQLite database

&#x20;Security alert storage

&#x20;Database integration testing

In Progress

&#x20;Integrate ICMP flood detector into main packet processing

&#x20;SYN flood detection

&#x20;Additional network anomaly detection

&#x20;Adaptive risk scoring

&#x20;Machine learning model

&#x20;Machine learning evaluation

&#x20;Explainable alerts

&#x20;Web dashboard

Planned

&#x20;Complete hybrid IDS architecture

&#x20;Host-specific behavioral baseline

&#x20;Alert prioritization

&#x20;Dashboard graphs and statistics

&#x20;Performance evaluation

&#x20;Final testing

&#x20;Project documentation

&#x20;Final presentation

&#x20;Viva preparation

Current Detection Modules

1\. Port Scan Detection



The system monitors destination ports contacted by a source IP.



If a source contacts a large number of different ports within a short time window, the system generates a possible port scan alert.



Current threshold:



10 different ports within 10 seconds

2\. General Flood Detection



The system monitors packet activity from each source IP.



If a source sends a large number of packets within a short time window, a possible flooding alert is generated.



Current threshold:



20 packets within 5 seconds

3\. ICMP Flood Detection



The system separately monitors ICMP packet activity.



If a source generates a high number of ICMP packets within a short time window, a possible ICMP flood alert is generated.



Current threshold:



10 ICMP packets within 5 seconds

Database



Security alerts are stored using SQLite.



The database contains information such as:



Alert ID

Timestamp

Source IP

Destination IP

Attack type

Severity

Detection details



The generated SQLite database is intentionally excluded from GitHub using .gitignore.



Project Structure

CN\_IDS\_Project

|

+-- main.py

+-- packet\_sniffer.py

+-- packet\_parser.py

+-- statistics.py

+-- database.py

|

+-- test\_port\_scan.py

+-- test\_flood.py

+-- test\_icmp\_flood.py

+-- test\_database.py

+-- test\_alert\_database.py

|

+-- detectors

|   +-- \_\_init\_\_.py

|   +-- port\_scan.py

|   +-- flood\_detector.py

|   +-- icmp\_flood.py

|

+-- README.md

+-- .gitignore

How to Run

Start the network monitoring system

python main.py



The system captures network packets and displays packet information and network statistics.



Test Port Scan Detection

python test\_port\_scan.py

Test Flood Detection

python test\_flood.py

Test ICMP Flood Detection

python test\_icmp\_flood.py

Test Database

python test\_database.py

Test Alert Database Integration

python test\_alert\_database.py

Future Hybrid Detection Approach



The planned system will combine multiple detection signals.



A proposed risk score is:



Risk Score =

0.35 × Rule Score

\+

0.35 × ML Score

\+

0.20 × Anomaly Score

\+

0.10 × Historical Score



The resulting score will be mapped to security levels such as:



0–25    SAFE

26–50   LOW

51–70   MEDIUM

71–85   HIGH

86–100  CRITICAL



These values are part of the proposed design and may be adjusted during evaluation.



Safety and Testing



Testing of network-security detection functionality should be performed only on systems and networks where testing is authorized.



The project uses simulated packet information for detector testing to avoid generating unauthorized network attacks.



Project Development Plan

Week 1

Packet capture

Packet parsing

Network statistics

Database

Initial rule-based detection

Week 2

Additional detection techniques

Alert management

Risk scoring

Network anomaly features

Week 3

Dataset preparation

Machine learning

Model evaluation

Integration with IDS

Week 4

Dashboard

Testing

Performance evaluation

Documentation

Presentation

Viva preparation







