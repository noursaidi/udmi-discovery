SETUP FILES
===========

**udmi-config.json** contains all of the settings for the udmi discovery tool:

    "server":       "http://localhost",
    "site":         "Local",
    "username":     "Partner",
    "password":     "RGVtb29tZUQ=",
    "eweb-id":      7,
    "mqtt-config":  "mqtt.json",
    "omit-devices": ["enteliWEB","CopperCube","enteliCLOUD"],
    "gateway-id":   "GAT-102",
    "gateway-addr": "4124019",
    "telemetry":    "telemetry-objects.json",
    "substitution": "ontology-substitution-list.txt",
    "units":        "units-exchange.json",
    "dev-xref":     "device-xref.json",
    "use-tags":     true,
    "read-file-data": false,
    "commissioned-flag": false,
    "excludes":     "exclude-list.txt",
    "write-to-file": false

mqtt-config.json contains the GCP connection parameters for the udmi discovery tool:


telemetry-objects.json contains a list of the BACnet objects that are to be considered for inclusion in the telemetry pointset


ontology-substition-list.txt is a list of characters that are to replaced with an underscore so as to better match the Digital Buildings Ontology


units-exchange.json contains a map of engineering units to those permitted in the Digital Buildings Ontology (e.g. "°C" = "degrees-Celsius")


device-xref.json contains a map of BACnet device names to Digital Buildings Ontology compliant formats


exclude-list.txt contains a list of strings that if found in an object name cause that object to be excluded from the telemetry pointset


Installation instructions:
==========================

1) Install pip - sudo apt install python3-pip
2) Install enteliWEB (Linux build, supports Ubuntu 20.04 LTS):
    a) cd [path to]/lpcU20
    b) sudo ./install.sh
    c) dlmgrcmd add online [license serial number]
    d) enter license details
2) In a browser:
    a) http://localhost/enteliweb
    b) Goto 'settings' menu
    c) Goto 'sites' menu, create a new site called Local, add UDP/IP Connection
    c) Goto 'users' menu, create a new user in Administrators group; username 'Partner'; password 'DemoomeD'. Set timeout to 0 (Never)
    d) Optional - set user timeout of 'admin' user to 0 (Never)
    e) Goto 'Navigation' tab on LHS accordian. Check for BACnet devices on the device tree
3) Install paho-mqtt library - sudo pip3 install paho-mqtt
4) Setup systemctl to run discovery on a timed basis:
    a) cd $HOME/udmi-discovery
    b) sudo cp udmi-discovery.timer /usr/lib/systemd/system
    c) sudo cp udmi-discovery.service /usr/lib/systemd/system
    d) cp udmi-discovery.sh ./
    e) chmod 775 ../udmi-discovery.sh
    f) systemctl enable udmi-discovery.timer
6) Note: udmi-discovery.timer defaults to running every 15 minutes, to modify:
    a) sudo nano /usr/lib/systemd/system/udmi-discovery.timer
    b) edit 'OnCalendar' term to required interval
    c) save & exit
    d) systemctl daemon-reload
7) To check the time of the next scheduled run - systemctl list-timers
8) To view the log - cat /var/log/syslog | grep "udmi-discovery"

    
