This does a couple of things:

- Converts masscan XML format to nmap XML
- Allows you to feed NMAP already discovered hosts and ports via an nmap XML file

Usage:
Intended usgae is to run initial scan with masscan (since its faster) then conduct the service scan via nmap based on the results

TODO:
- Add more fields for the masscan conversion script (XML)
- Maybe put it all in the read_ports script????? <-- this alot of work
- Add support for GREP output file
