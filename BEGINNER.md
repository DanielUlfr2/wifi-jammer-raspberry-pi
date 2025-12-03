# Beginner Guide

## What is this project?
Cypher CC1101 Jammer is an open-source RF pentesting platform built around a WEMOS D1 Mini ESP8266 and a CC1101 radio module. It allows you to scan, transmit, jam, and replay sub-GHz signals through a simple command-line interface. The firmware aims to provide a flexible alternative to more expensive hardware while remaining hackable and easy to extend.

## Getting Started
1. **Hardware** – A WEMOS D1 Mini (ESP8266) and a CC1101 module wired according to the schematic.
2. **Firmware** – Flash the `cc1101-tool-esp8266.ino` sketch onto the ESP8266 using the Arduino IDE or similar tools.
3. **Connecting** – After flashing, connect via serial terminal or telnet (for Wi-Fi builds) to access the CLI and issue commands such as `setmhz`, `scan`, `tx`, and `jam`.

## Safety and Legal Precautions
- **Know the law** – Radio jamming and transmission on unauthorized frequencies may be illegal in many regions. Operate only on bands and power levels allowed in your jurisdiction.
- **Use responsibly** – Test only on devices and frequencies you own or have explicit permission to experiment with. Avoid interfering with public services or other people's equipment.
- **RF exposure** – Even low-power transmitters can cause interference or exceed regulatory limits. Maintain proper distance from antennas and avoid transmitting near sensitive equipment.
- **Ethical use** – This tool is provided for education and security research. Do not use it for malicious or disruptive activities.

## Additional Tips
- Start by experimenting on low-power settings and in a shielded or isolated environment.
- Review the project's `README.md` for advanced commands, changelog, and hardware details.
- Join community forums or groups to learn from experienced users and share responsible practices.

Happy hacking and stay safe!
