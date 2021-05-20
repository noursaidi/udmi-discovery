
Examples for BACnet device / object / property discover using REST API provided by enteliWEB Software

URL for enteliWEB - e.g. http://localhost

Authenticate using OAuth 2.0 with Usernameand Password (encrytped)

BACnet Site Name - e.g. Local

example REST calls:

To get a list of BACnet devicesas a JSON dictionary:-

GET ('http://localhost/enteliweb/api/.bacnet/Local?alt=json')

To get a list of BACnet objects within a BACnet device:-

GET ('http://localhost/enteliweb/api/.bacnet/Local/101?alt=json')

To get a list of BACnet properties within a BACnet object of a BACnet device:-

GET ('http://localhost/enteliweb/api/.bacnet/Local/101/analog-input,1?alt=json

To get one specific BACnet property from a BACnet object of a BACnet device:-

GET ('http://localhost/enteliweb/api/.bacnet/Local/101/analog-input,1/present_value?alt=json
(note the 'Property Name' must be a BACnet property as defined in ISO-16484-5

Supports BACnet Rev 19
