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
2) Install enteliWEB (Linux build, supports Ubuntu 20.04 LTS):<br />
    a) cd [path to]/lpcU20<br />
    b) sudo ./install.sh<br />
    c) dlmgrcmd add online [license serial number]<br />
    d) enter license details<br />
2) In a browser:<br />
    a) http://localhost/enteliweb<br />
    b) Goto 'settings' menu<br />
    c) Goto 'sites' menu, create a new site called Local, add UDP/IP Connection<br />
    d) Goto 'users' menu, create a new user in Administrators group; username 'Partner'; password 'DemoomeD'. Set timeout to 0 (Never)<br />
    e) Optional - set user timeout of 'admin' user to 0 (Never)<br />
    f) Goto 'Navigation' tab on LHS accordian. Check for BACnet devices on the device tree<br />
3) Install paho-mqtt library - sudo pip3 install paho-mqtt<br />
4) Setup systemctl to run discovery on a timed basis:<br />
    a) cd $HOME/udmi-discovery<br />
    b) sudo cp udmi-discovery.timer /usr/lib/systemd/system<br />
    c) sudo cp udmi-discovery.service /usr/lib/systemd/system<br />
    d) cp udmi-discovery.sh ./<br />
    e) chmod 775 ../udmi-discovery.sh<br />
    f) systemctl enable udmi-discovery.timer<br />
6) Note: udmi-discovery.timer defaults to running every 15 minutes, to modify:<br />
    a) sudo nano /usr/lib/systemd/system/udmi-discovery.timer<br />
    b) edit 'OnCalendar' term to required interval<br />
    c) save & exit<br />
    d) systemctl daemon-reload<br />
7) To check the time of the next scheduled run - systemctl list-timers<br />
8) To view the log - cat /var/log/syslog | grep "udmi-discovery"<br />

    
