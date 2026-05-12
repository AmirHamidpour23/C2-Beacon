OUR ONLY DELIVERABLES ARE C2_Beacon.py, encrypt.py and beacon.c. Any other files were used for testing or 
deprecated versions that were used for referenceing

As a final project for Reverse Malware Engineering (CSC-4820), we created Project Aegis. It is a custom C2 
framework developed by the mock Cybershield Solutions Threat Intelligence Team in order to simulate an experience
of beacon‑to‑server demonstration to promote analysis skills. It acted as a touchstone for malware analysis and 
programming zomibes in a controlled lab environment. Amir Hamdipout (AmirDev) as the primary contributor, and 
Kamryn Wagner as the supportive analyst. The project consists of a Windows beacon client written in C and a 
multithreaded Python C2 server, a slideshow presentation, and an in depth report of the experience overall. 
The software uses encrypted and obfuscated communications with regular heartbeat check‑ins to blend beacon 
traffic into normal network activity while maintaining a reliable connection. Core features include remote 
command execution, system profiling, bidirectional file transfer, screenshot capture, privilege escalation, 
and multiple persistence mechanisms, all controlled through an interactive server interface capable of handling 
multiple concurrent beacons from different devices. The C2 server presents a simple control menu, accepts new 
connections, assigns each beacon a unique session ID, and tracks active sessions with metadata such as socket, 
IP/port, and timestamps so the operator can list and interact with all compromised hosts from a single panel. 
Per‑beacon listener threads continuously decrypt and parse JSON messages, pushing heartbeats, command responses, 
file transfers, or screenshots and routing them to the appropriate queues for the operator to review. This repo contains 
the details on the beacon and framework connection and the encryption for the payloads. 
