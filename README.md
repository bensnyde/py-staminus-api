py-staminus-api
===============

Staminus API Python Library

http://support.staminus.net/index.php?action=artikel&cat=11&id=19&artlang=en

Usage
---

staminus = Staminus('xx', 'xx', 'xx://', 'xx', 'xx')

secure_ports = []
for secure_port in staminus.get_secure_ports():
    secure_ports.append(staminus.get_secure_port(secure_port['secureport_ID'])) 


servers = []
for server in staminus.get_servers():
    for entry in server['addons']:
        if entry['serverID'] not in servers:
            servers.append(entry['serverID'])

            
attacks = []
for server in servers:
    attacks.append(staminus.get_attack_logs(server))
