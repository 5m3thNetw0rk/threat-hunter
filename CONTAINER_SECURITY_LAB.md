📦 Case Study: Container Escape & Lateral Movement Detection

Project: Container Security Monitor (container_monitor.py)
Environment: Parrot OS / Docker Audit Logs

🕵️ Analysis of Detected Alerts

During the technical assessment of the container_audit.log, the monitoring tool identified two critical escape vectors:

1. Privileged Container Launch (--privileged)

The Threat: Attacker launched a container with the --privileged flag.

The Risk: This bypasses the Linux kernel's isolation boundaries. A privileged container can see and interact with host devices (like /dev/sda) just like the root user on the host OS.

Mitigation: Enforce Docker Security Profiles (AppArmor/Seccomp) and prohibit the use of --privileged in production via Admission Controllers.

2. Docker Socket Mounting (/var/run/docker.sock)

The Threat: A container was detected mounting the host's Docker socket.

The Risk: This is "Docker-in-Docker" exploitation. An attacker inside this container can send API commands to the host's Docker daemon to create a new, malicious container with a root-level mount of the host's filesystem.

Mitigation: Never mount the Docker socket inside a container unless it is for a specific monitoring tool that has been heavily hardened and isolated.

🛠️ Detection Methodology

The container_monitor.py uses signature-based detection via Python Regex to scan system and audit logs for specific command-line arguments and mount points that align with MITRE ATT&CK Technique T1611 (Escape to Host).

Analyst Note: This module rounds out the 'Defense in Depth' strategy by providing visibility into the abstraction layer of containerized applications.
