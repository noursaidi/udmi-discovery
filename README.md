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


