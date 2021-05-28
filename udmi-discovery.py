
#!/usr/bin/env python

# eWeb-Discovery.py

# Version 0.02 - Updated to handle Public Key from either CSVXXXX.Description property in case host eWeb does not support read from file by the API
#
# Code for discovering BACnet devices and objects via enteliWEB REST API
# Creates file/folder structrue for DAQ Registrar Tool
#
import sys
import argparse
import datetime
import os
import random
import time
import json
import requests
import codecs
import shutil
import base64

import ssl
import jwt
import paho.mqtt.client as mqtt

# cryptography module imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from dbOntology import DigitalBuildingsOntology

INTERFACE_NAME = "Delta UDMI Discovery Tool for Google DAQ Registrar"

TRUE_LIST =  [1,True,"True","true","TRUE"]
BACNET_SERVER_PATH = '/var/lib/DeltaControls/BACnetServer'
METADATA_FILE = 'metadata.json'
RSA_PUBLIC_FILE = 'rsa_public.pem'
DEFAULT_METADATA_TEMPLATE = {
  "version": 1,
  "timestamp": "2018-08-26T21:39:29.364Z",
  "local_id": "92EA09",
  "protocol": "bacnet",
  "points": {
  }
}

DEFAULT_DEBUG_LEVEL = 4

class UDMIDiscovery():

    MAXIMUM_BACKOFF_TIME = 32
    MQTT_BACKOFF_TIME = 5
    
    PUBLIC_KEY_FIL_NAME = "Google Cloud IoT UDMI Public Key"
    GOOGLE_ROOTS_FIL_NAME = "Google Cloud IoT Gateway Roots"
    PRIVATE_KEY_FILE = "rsa_private.pem"
    PUBLIC_KEY_FILE = "rsa_public.pem"
    GOOGLE_ROOTS_FILE = "google_roots.pem"
    MODULE_FILE = os.path.abspath(__file__)
    JWT_EXP_MINS = 20

    def __init__ (self, debug=DEFAULT_DEBUG_LEVEL, configuration_file=None, metatemplate=None):

        try:
            self.configuration_file = configuration_file
            self.debug = debug
            self.server = None
            self.site = None
            self.username = None
            self.password = None
            self.eweb_id = None
            self.metadata_template = metatemplate

            self.configuration_loaded = False

            self.config_object = None
            self.config_string = None

            self.certificates_dir = None
            self.private_key_path = None
            self.public_key_path = None
            self.google_roots_path = None
            self.public_key_pem = None
            
            self.state_telemetry_topic = '/devices/{GWID}/state'
            self.metadata_topic = '/devices/{GWID}/events/{DID}/meta'

            self.public_key = ''
            self.read_file_data = False
            self.commissioned_flag = False
            self.write_to_file = False
            self.telemetry_objects = ''
            self.ontology_substitution = ''
            self.units_exchange = ''
            self.ontology = None
            self.excludes = ''
            self.xref = ''
            self.device_count = 0
            self.object_count = 0

            self.mqtt_config = None
            self.GCP_hostName = None
            self.GCP_tcpPort = None
            self.GCP_location = None
            self.GCP_project = None
            self.GCP_registry = None
            self.GCP_device = None
            self.should_backoff = True

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Google IoT Gateways Constructor"
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))

    def printd(self, message, level=2):
        # If debug is on via global DEBUG = True then print messages
        #    :param message:
        #    :param: level: the level of the print statement
        #    :return: nothing

        if self.debug >= level:
            print(message)


    def __logError(self, message=None, error=None, filename=None, linenumber=None, level=None):
        # If there is a message Pop the oldest error off the list and add the new error with time stamp and write it to the
        # CSV object description.

        # If the message is none simply write the error log to the CSV object description.

        #    :param message: String/None - error message to time stamp and add, None only write to CSV Object description
        #    :param error: String - error code such as error error
        #    :param filename: String/None - optional filename generating the error
        #    :param linenumber: String/None - optional the lineno the error was generated on
        #    :return: Nothing

        try:
            if self.config_object is None:
                return

            # if we have message time stamp it
            if (level <= self.debug) and message is not None:
                time_string = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                error_string = "{timestamp}: {message}".format(timestamp=time_string, message=message)
            else:
                error_string = None

            # Check it we have to add the message
            if error_string is not None:

                # Generate the error message
                self.printd("{user}:{error} - {file}:{line}".format(user=error_string, error=error, file=filename, line=linenumber),level=level)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.printd("Logging Error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=0)


    def get_certificates_path(self):
        # Gets the path on disk where certificates are stored.

        data_path = BACNET_SERVER_PATH
        data_path_parts = os.path.split(data_path)
        certificates_path = os.path.join(data_path_parts[0], "Certificates", "Google Cloud MQTT")
        
        if not os.path.exists(certificates_path):
            os.makedirs(certificates_path)
            
        return certificates_path
        
        
    def __check_private_key(self):

        try:
            self.printd("Checking private key in {}...".format(self.private_key_path), level=1)
            if not os.path.isfile(self.private_key_path):
                self.printd("Creating private key...", level=1)
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
                self.printd("Writing private key to {}...".format(self.private_key_path), level=1)
                file = open(self.private_key_path, "wb")
                file.write(pem) 
                file.close()
                self.printd("Private key created.", level=1)
            if not os.path.isfile(self.google_roots_path):
                shutil.copyfile(self.default_google_roots, self.google_roots_path)
                self.printd("Google roots copied to {}".format(self.google_roots_path), level=1)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Private Key Check"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def init(self):
        # Initialise

        try:
            self.printd ("UDMI Discovery Initialised", level=2)

            self.certificates_dir = self.get_certificates_path()
            self.google_roots_path = os.path.join(self.certificates_dir, self.GOOGLE_ROOTS_FILE)
            self.private_key_path = os.path.join(self.certificates_dir, self.PRIVATE_KEY_FILE)
            self.public_key_path = os.path.join(self.certificates_dir, self.PUBLIC_KEY_FILE)
            self.default_google_roots = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Certificates", self.GOOGLE_ROOTS_FILE)
            self.default_public_key = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Certificates", self.PUBLIC_KEY_FILE)
            self.printd("Default google roots path: {path}".format(path=self.default_google_roots), level=1)

            self.__check_private_key()            

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error creating class"
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def load_configuration(self):
        # Verifies and loads the configuration file and configures the interface as needed.

        # return: Nothing

        try:
            # load config
            if self.configuration_file:
                self.printd("Configuration Path={path}".format(path=self.configuration_file), level=1)
                # read in configuration JSON

                try:
                    with open(self.configuration_file) as json_file:  
                        self.config = json.load(json_file)

                    self.server = self.config["server"]
                    self.site = self.config["site"]
                    self.username = self.config["username"]
                    self.password = base64.b64decode(self.config["password"]).decode('utf-8')
                    self.eweb_id = self.config["eweb-id"]
                    self.gateway_id = self.config["gateway-id"]
                    self.gateway_addr = self.config["gateway-addr"]

                    if "omit-devices" in self.config:
                        self.omit_devices = self.config["omit-devices"]
                    else:
                        self.omit_devices = None

                    if "telemetry" in self.config:
                        if os.path.exists(self.config["telemetry"]):
                            try:
                                with open(self.config["telemetry"]) as json_file:
                                    self.telemetry_objects = json.load(json_file)

                            except:
                                raise Exception ("Error with Telemetry Dictionary {}".format(self.config["telemetry"]))

                    if "substitution" in self.config:
                        if os.path.exists(self.config["substitution"]):
                            try:
                                with open(self.config["substitution"]) as io_file:
                                    self.ontology_substitution = io_file.readlines()

                            except:
                                raise Exception ("Error with Ontology Substitution List {}".format(self.config["substitution"]))

                    if "units" in self.config:
                        if os.path.exists(self.config["units"]):
                            try:
                                with open(self.config["units"], encoding='utf-8') as json_file:
                                    self.units_exchange = json.load(json_file)

                            except:
                                raise Exception ("Error with Units Exchange Dictionary {}".format(self.config["units"]))

                    if "excludes" in self.config:
                        if os.path.exists(self.config["excludes"]):
                            try:
                                with open(self.config["excludes"]) as io_file:
                                    self.excludes = io_file.readlines()

                            except:
                                raise Exception ("Error with Excludes List {}".format(self.config["excludes"]))

                    if "dev-xref" in self.config:
                        if os.path.exists(self.config["dev-xref"]):
                            try:
                                with open(self.config["dev-xref"]) as json_file:
                                    self.xref = json.load(json_file)

                            except:
                                raise Exception ("Error with Device XRef List {}".format(self.config["dev-xref"]))

                    if "use-tags" in self.config:
                        self.use_tagging = True if self.config["use-tags"] in TRUE_LIST else False
                        self.ontology = DigitalBuildingsOntology()
                        self.entities = self.ontology.entityTypes
                    else:
                        self.use_tagging = False

                    if "read-file-data" in self.config:
                        self.read_file_data = True if self.config["read-file-data"] in TRUE_LIST else False

                    if "commissioned-flag" in self.config:
                        self.commissioned_flag = True if self.config["commissioned-flag"] in TRUE_LIST else False

                    if "write=to=file" in self.config:
                        self.write_to_file = True if self.config["write-to-file"] in TRUE_LIST else False

                    if "mqtt-config" in self.config:
                        if os.path.exists(self.config["mqtt-config"]):
                            with open(self.config["mqtt-config"]) as json_file:  
                                self.mqtt_config = json.load(json_file)

                            self.GCP_hostName = self.mqtt_config["hostName"]
                            self.GCP_tcpPort = self.mqtt_config["tcpPort"]
                            self.GCP_location = self.mqtt_config["location"]
                            self.GCP_project = self.mqtt_config["project"]
                            self.GCP_registry = self.mqtt_config["registry"]
                            self.GCP_device = self.mqtt_config["device"]

                except:
                    raise Exception ("Error Configuration file {}".format(self.configuration_file))

            self.configuration_loaded = True

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            self.configuration_loaded = False

            if self.debug > 0:
                raise Exception("{error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{error}".format(error=error))

    def create_jwt(self, project_id, private_key_file, algorithm):
        # Creates a JWT (https://jwt.io) to establish an MQTT connection.
        #    Args:
        #     project_id: The cloud project ID this device belongs to
        #     private_key_file: A path to a file containing either an RSA256 or
        #             ES256 private key.
        #     algorithm: The encryption algorithm to use. Either 'RS256' or 'ES256'
        #    Returns:
        #        An MQTT generated from the given project_id and private key, which
        #        expires in 20 minutes. After 20 minutes, your client will be
        #        disconnected, and a new JWT will have to be generated.
        #    Raises:
        #        ValueError: If the private_key_file does not contain a known key.

        try:
            token = {
                    # The time that the token was issued at
                    'iat': datetime.datetime.utcnow(),
                    # The time the token expires.
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=self.JWT_EXP_MINS+5),
                    'aud': project_id
            }

            # Read the private key file.
            with open(private_key_file, 'r') as f:
                private_key = f.read()

            self.printd('Creating JWT using {} from private key file {}'.format(
                    algorithm, private_key_file), level=1)

            return jwt.encode(token, private_key, algorithm=algorithm)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Create JWT"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def db_synchronize(self):
        try:
            # Get the object list from the eWeb Device
            self.url = "{}/enteliweb/api/.bacnet/{}/{}?alt=json".format(self.server, self.site, self.eweb_id)
            res = self.get_from_api()
            if res.status_code != 200:
                self.printd("Failed to GET FIL objects from eWeb API (Error = {})".format(res.status_code),level=1)
                fils = {}
            else:
                fils = json.loads(res.text)

            found_public_key = False
            for k in fils:
                if 'file' in k:
                    # write the public key to FIL
                    public_key_object = fils[k]["displayName"]
                    if public_key_object == self.PUBLIC_KEY_FIL_NAME:
                        # update file_data.diskpath property of FIL object
                        found_public_key = True
                        obj_ref = k
                        sp_obj = obj_ref.split(',')
                        obj_inst = sp_obj[1]
                        self.url = "{}/enteliweb/api/.bacnet/{}/{}/FIL,{}/description?alt=json".format(self.server, self.site, self.eweb_id, obj_inst)
                        if os.path.exists(self.public_key_path):
                            file = open(self.public_key_path, "r")
                            self.public_key_pem = file.read()
                            file.close()
                        else:
                            self.printd("Not Found {}".format(self.public_key_path),level=4)
                            if self.public_key_pem is None:
                                # generate the pem from the private key
                                with open(self.private_key_path, "rb") as key_file:
                                    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                                public_key = private_key.public_key()
                                temp_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                                self.public_key_pem = temp_pem.decode('utf-8')
                                file = open(self.public_key_path, "wb")
                                file.write(temp_pem)
                                file.close()
                                self.__logError(message="Public key created", level=2)
                                self.printd("Writing Public Key to {}".format(public_key_object),level=4)
                                if os.path.isfile(self.public_key_path):
                                    shutil.copyfile(self.public_key_path, self.default_public_key)
                                    self.printd("Public Key copied to {}".format(self.public_key_path), level=1)


                        json_data = {"$base": "String", "value":self.public_key_pem}
                        self.put_to_api(json_data)

            if not found_public_key:
                # Public Key FIL Object not found - clear out old Public Key data
                self.public_key_pem = None
                if os.path.exists(self.public_key_path):
                    os.remove(self.public_key_path)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.printd("Update DB Error", level=1)


    def get_from_api(self):
        max_retries = 3
        try_no = 1
        success = False

        try:
            while not success and try_no < max_retries:
                res = requests.get(self.url,auth=(self.username,self.password),headers={'Content-Type': 'application/json'})
                if res.status_code != 200:
                    print ("API Error {} from GET request {}".format(res.status_code,self.url))
                    print ("Attempt {} (of {}".format(try_no,max_retries))
                    try_no += 1
                else:
                    success = True
            
            return res
        
        except Exception as error:
            pass

    def put_to_api(self, json_data):
        max_retries = 3
        try_no = 1
        success = False

        try:
            while not success and try_no < max_retries:
                res = requests.put(self.url, data=json.dumps(json_data), auth=(self.username,self.password),headers={'Content-Type': 'application/json'})
                if res.status_code != 200:
                    self.printd ("API Error {} from PUT request {}".format(res.status_code,self.url),level=3)
                    self.printd ("Attempt {} (of {}".format(try_no,max_retries),level=3)
                    try_no += 1
                else:
                    success = True
            
            return res
        
        except Exception as error:
            pass

    def mqtt_error_str(self, rc):
        # Convert a Paho error to a human readable string.
        return '{}: {}'.format(rc, mqtt.error_string(rc))


    def on_connect(self, client, unused_userdata, unused_flags, rc):
        # Callback for when a device connects.
        user_error = mqtt.connack_string(rc)
        self.printd("On Connect: {} - [{}]".format(user_error, rc), level = 1)

        if rc == 0:
            # After a successful connect, reset backoff time and stop backing off.
            self.should_backoff = False
            self.minimum_backoff_time = 1
            self.__logError(message="Connected to Google cloud", level=0)
            # Subscribe to Gateway Device topics
            self.subscribe_gw_topics(client)
        else:
            self.should_backoff = True
            self.mqtt_client.disconnect()
            self.__logError(message="Connection failed: {}".format(rc), level=0)


    def subscribe_gw_topics(self, client):
        # Subscribe to the config topic.
        mqtt_config_topic = '/devices/{}/config'.format(self.GCP_device)
        self.printd('Subscribing to {}'.format(mqtt_config_topic), level=4)
        client.subscribe(mqtt_config_topic, qos=1)

        # Subscribe to the commands topic, QoS 1 enables message acknowledgement.
        mqtt_command_topic = '/devices/{}/commands/#'.format(self.GCP_device)
        self.printd('Subscribing to {}'.format(mqtt_command_topic), level=4)
        client.subscribe(mqtt_command_topic, qos=0)

        # The topic gateways receive error updates on. QoS must be 0.
        error_topic = '/devices/{}/errors'.format(self.GCP_device)
        self.printd ('Subscribing to {}'.format(error_topic), level=4)
        client.subscribe(error_topic, qos=0)

#        state_topic = self.state_telemetry_topic.format(GWID=self.GCP_device)


    def on_disconnect(self, unused_client, unused_userdata, rc):
        # Paho callback for when a device disconnects.
        user_error = 'Google mqtt: on_disconnect', self.mqtt_error_str(rc) 
        self.printd(user_error, level=0)

        # Since a disconnect occurred, the next loop iteration will wait with
        # exponential backoff.
        self.should_backoff = True


    def on_publish(self, unused_client, unused_userdata, mid):
        # Paho callback when a message is sent to the broker.
        time.sleep(self.MQTT_BACKOFF_TIME)


    def on_message(self, unused_client, unused_userdata, message):
        # Callback when the device receives a message on a subscription
        message_str = message.payload.decode('utf-8')
#        message_dict = json.loads(message.payload)
        self.printd("Google MQTT MESSAGE received topic: <{topic}>   message: <{message}>".format(topic=message.topic, message=message_str), level=4)
        self.__logError(message="MQTT MESSAGE from : <{topic}>".format(topic=message.topic), level=4)


    def get_mqtt_client(
            self, project_id, cloud_region, registry_id, device_id, private_key_file,
            algorithm, ca_certs, mqtt_bridge_hostname, mqtt_bridge_port):
        # Create our MQTT client. The client_id is a unique string that identifies
        # this device. For Google Cloud IoT Core, it must be in the format below.

        client_id = 'projects/{}/locations/{}/registries/{}/devices/{}'.format(
                project_id, cloud_region, registry_id, device_id)
        self.printd('Device client_id is \'{}\''.format(client_id), level=1)

        client = mqtt.Client(client_id=client_id)

        # With Google Cloud IoT Core, the username field is ignored, and the
        # password field is used to transmit a JWT to authorize the device.
        client.username_pw_set(
                username='unused',
                password=self.create_jwt(
                        project_id, private_key_file, algorithm))

        # Enable SSL/TLS support.
        client.tls_set(ca_certs=ca_certs, tls_version=ssl.PROTOCOL_TLSv1_2)

        # Register message callbacks. https://eclipse.org/paho/clients/python/docs/
        # describes additional callbacks that Paho supports. In this example, the
        # callbacks just print to standard out.
        client.on_connect = self.on_connect
        client.on_publish = self.on_publish
        client.on_disconnect = self.on_disconnect
        client.on_message = self.on_message

        self.printd("Connecting to {}:{}".format(mqtt_bridge_hostname,mqtt_bridge_port),level=4)
        # Connect to the Google MQTT bridge.
        rc = client.connect(mqtt_bridge_hostname, mqtt_bridge_port)
        self.printd("Return Code = {}".format(rc),level=4)

        time.sleep(self.MQTT_BACKOFF_TIME)

        client.loop_start()  # start loop to process received messages

        return client


    def run(self):
        # Queries eWeb REST API for devices then for each device creates a DAQ Registrar Folder/file structure

        device_no = 0
        object_no = 0

        try:
            self.load_configuration()
            self.__logError("Configuration loaded", level=2)

        except Exception as error:
            self.printd("Configuration load error {err}".format(err=error), level=1)
            self.__logError(message="Configuration loading error: {}".format(error), level=1)

        if self.configuration_loaded:
            try:
                self.db_synchronize()

                self.printd("self.configuration_loaded; Connecting to MQTT",level=2)
                self.__logError(message="self.configuration_loaded; Connecting to MQTT", level=1)
                jwt_iat = datetime.datetime.utcnow()
                self.mqtt_client = self.get_mqtt_client(
                    self.GCP_project, self.GCP_location, self.GCP_registry,
                    self.GCP_device, self.private_key_path, "RS256",
                    self.google_roots_path, self.GCP_hostName, self.GCP_tcpPort)

            except Exception as error:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

                self.printd("get_mqtt_client({},{},{},{},{},{},{},{},{}) failed".format( \
                    self.GCP_project, self.GCP_location, self.GCP_registry, \
                    self.GCP_device, self.private_key_path, "RS256", \
                    self.google_roots_path, self.GCP_hostName, self.GCP_tcpPort),level=4)
                self.printd("Error connecting:", level = 2)
                self.__logError("Error connecting:", level = 2)
                self.__logError(message="Error connecting", filename=filename, linenumber=exc_tb.tb_lineno, level=1)

            time.sleep(self.MQTT_BACKOFF_TIME)

            if self.should_backoff == False:
                # Connected to IoT Core
                try:
                    self.db_synchronize()

                    # Construct URL from settings
                    self.url = "{}/enteliweb/api/.bacnet/{}?alt=json".format(self.server, self.site)

                    # Call Get Request to retreive all devices from the current site
                    res = self.get_from_api()

                    devices = json.loads(res.text)
                    self.device_count = len(devices)

                    # Read Metadata template
                    self.metadata = {}
                    if os.path.exists(self.metadata_template):
                        with open(self.metadata_template) as json_file:  
                            self.metadata = json.load (json_file)
                    elif "system" in self.config:
                        self.metadata["system"] = self.config["system"]
                    else:
                        self.metadata["system"] = DEFAULT_METADATA_TEMPLATE

                    if self.write_to_file:
                        # Create 'misc' folder
                        if not os.path.exists('misc'):
                            os.makedirs('misc')

                        # Create site folder in 'misc'
                        site_folder = self.site.lower()
                        site_folder = site_folder.replace(' ', '_')
                        site_folder = 'misc/{}'.format(site_folder)
                        if not os.path.exists(site_folder):
                            os.makedirs(site_folder)
                        # Create 'devices'  folder in 'misc/{site}'
                        if not os.path.exists('{}/devices'.format(site_folder)):
                            os.makedirs('{}/devices'.format(site_folder))

                    gw_meta = dict(self.metadata)
#                    gw_meta["version"] = self.metadata["version"]
#                    gw_meta["timestamp"] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
#                    gw_meta["hash"] = self.metadata["hash"]
#                    gw_meta["system"] = self.metadata["system"]
                    str_gwname = self.gateway_id

                    str_gw_meta = '{"proxy_ids": ['
                    gw_meta_need_comma = False
                    for dev in devices:
                        device_no += 1
                        str_dev_id = dev
                        if str_dev_id.isnumeric():
                            str_dname = str(devices[dev]["displayName"])
                            if str_dname in self.xref.keys():
                                str_dname = self.xref[str_dname]
                            print ("Name = {} ({}/{})".format(str_dname,device_no,self.device_count))
                            # Get the Vendor Id
                            self.url = "{}/enteliweb/api/.bacnet/{}/{}/DEV,{}/vendor-identifier?alt=json".format(self.server, self.site, dev, dev)
                            res = self.get_from_api()
                            if res.status_code != 200:
                                self.printd("Failed to GET BACnet Device Vendor_Identifier from eWeb API (Error = {})".format(res.status_code),level=0)
                                vendor_identifier = {}
                            else:
                                vendor_identifier = json.loads(res.text)
                            # Check to see if this is a device that we should skip
                            self.url = "{}/enteliweb/api/.bacnet/{}/{}/DEV,{}/model-name?alt=json".format(self.server, self.site, dev, dev)
                            res = self.get_from_api()
                            if res.status_code != 200:
                                self.printd("Failed to GET BACnet Device Model_Name from eWeb API (Error = {})".format(res.status_code),level=0)
                                model_name = {}
                            else:
                                model_name = json.loads(res.text)
                            if not model_name["value"] in self.omit_devices:
                                # Add proxy device to list in Gateway Metadata Config Block
                                if gw_meta_need_comma:
                                    str_gw_meta += ','
                                else:
                                    gw_meta_need_comma = True
                                str_gw_meta += '"' + str_dname + '"'

                                # Check format of Device Name - no spaces, no underscores
                                str_dname = str_dname.replace(' ', '-')
                                str_dname = str_dname.replace('_', '-')

                                if self.write_to_file:
                                    # Create device folder in 'misc/{site}/devices'
                                    device_folder = '{}/devices/{}'.format(site_folder,str_dname)
                                    if not os.path.exists(device_folder):
                                        os.makedirs(device_folder)

                                meta = dict(self.metadata)
                                meta["points"] = {}
                                meta["local_id"] = str_dev_id

                                # Call Get Request to retreive all objects from the current Device
                                self.url = "{}/enteliweb/api/.bacnet/{}/{}?alt=json".format(self.server, self.site, dev)
                                res = self.get_from_api()
                                if res.status_code != 200:
                                    self.printd("Failed to GET BACnet Object list from eWeb API (Error = {} - Using empty set)".format(res.status_code),level=0)
                                    objects = {}
                                objects = json.loads(res.text)
                                self.object_count = len(objects)
                                object_no = 0
                                for obj in objects:
                                    object_no += 1
                                    sp_obj = obj.split(',')
                                    if sp_obj[0] in self.telemetry_objects.keys():
                                        if self.commissioned_flag:
                                            # If this is a Delta Controls (Vendor Id = 8) device AND the Commissioned Flag is Set, include in the telemetry
                                            if vendor_identifier["value"] == "8":
                                                # This is a Delta Controls device - check the 'Commissioned Flag' to include in Telemetry
                                                # Get the Application Software Version
                                                self.url = "{}/enteliweb/api/.bacnet/{}/{}/DEV,{}/application_software_version?alt=json".format(self.server, self.site, dev, dev)
                                                res = self.get_from_api()
                                                if res.status_code != 200:
                                                    self.printd("Failed to GET BACnet Device Application_Software_Version from eWeb API (Error = {})".format(res.status_code),level=0)
                                                    Commissioned = True # Force telemetry
                                                else:
                                                    app_sw = json.loads(res.text)
                                                    if app_sw["value"].startswith('V3.'):
                                                        if sp_obj[0] in ['analog-input','analog-output','binary-input','binary-output','multistate-input','multistate-output']:
                                                            self.url = "{}/enteliweb/api/.bacnet/{}/{}/{},{}/Commission_Flag?alt=json".format(self.server, self.site, dev, sp_obj[0], sp_obj[1])
                                                            res = self.get_from_api()
                                                            if res.status_code != 200:
                                                                self.printd("Failed to GET Commissioned Flag property eWeb API (Error = {})".format(res.status_code),level=0)
                                                                break
                                                            comm_flag = json.loads(res.text)
                                                            Commissioned = True if comm_flag["value"] == "1" else False
                                                        else:
                                                            Commissioned = True # No Commissioned Flag on object - force telemetry
                                                    elif app_sw["value"].startswith('4.'):
                                                        self.url = "{}/enteliweb/api/.bacnet/{}/{}/{},{}/Commissioned?alt=json".format(self.server, self.site, dev, sp_obj[0], sp_obj[1])
                                                        res = self.get_from_api()
                                                        if res.status_code != 200:
                                                            self.printd("Failed to GET Commissioned Flag property eWeb API (Error = {})".format(res.status_code),level=0)
                                                            break
                                                        comm_flag = json.loads(res.text)
                                                        Commissioned = True if comm_flag["value"] == "1" else False
                                                    else:
                                                        self.printd("Unknown Delta Controls Application Software Version - forcing telemetry",level=2)
                                                        Commissioned = True
                                            else:
                                                Commissioned = True # Not a DCI device - force telemetry
                                        else:
                                            Commissioned = True # enforced telemetry by config setting

                                        if Commissioned:
                                            str_obj = self.telemetry_objects[sp_obj[0]]
                                            self.printd ("{} ({}/{}): Telemetry Object ({}/{}) Found - {} ({})".format(str_dname,device_no,self.device_count,object_no,self.object_count,objects[obj]["displayName"], sp_obj),level=2)

                                            # Check format of Object Name - must be lower case, no spaces, no hyphens, no braces
                                            str_oname = str(objects[obj]["displayName"])
                                            str_oname = str_oname.lower()
                                            for str_subst in self.ontology_substitution:
                                                str_oname = str_oname.replace(str_subst.rstrip('\n'),'_')
                                            str_oname = str_oname.rstrip('_')

                                            ex_found = False
                                            entity_found = False

                                            for excl in self.excludes:
                                                if excl.rstrip().lower() in str_oname:
                                                    ex_found = True
                                                    break

                                            if self.use_tagging and not ex_found:
                                                # Check to see if the object name is in our tag list
                                                if self.ontology.checkForEntityType(str_oname):
                                                    entity_found = True

                                            if (not self.use_tagging or (self.use_tagging and entity_found)) and not ex_found:
                                                # Units
                                                if 'analog' in sp_obj[0].lower():
                                                    # Call Get Request to retrieve units property for this object
                                                    self.url = "{}/enteliweb/api/.bacnet/{}/{}/{},{}/units?alt=json".format(self.server, self.site, dev, sp_obj[0], sp_obj[1])
                                                    res = self.get_from_api()
                                                    if res.status_code != 200:
                                                        self.printd("Failed to GET Units property from eWeb API (Error = {})".format(res.status_code),level=0)
                                                        break
                                                    units = json.loads(res.text)
                                                    str_units = units["value"]
                                                    if str_units in self.units_exchange.keys():
                                                        str_units = self.units_exchange[str_units]
                                                    else:
                                                        str_units = 'No-units'
                                                else:
                                                    str_units = "No-units"

                                                meta["points"][str_oname] = json.loads('{"ref" : "'+str_obj+sp_obj[1] + '.Present_Value","units": "' + str_units + '"}')

                                if self.write_to_file:
                                    # Create metadata file
                                    metafile = '{}/devices/{}/{}'.format(site_folder,str_dname,METADATA_FILE)
                                    with open (metafile, "w") as outfile:
                                        json.dump(meta, outfile, indent=2)
                                meta["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
#                                meta_topic = self.metadata_topic.format(GWID=self.GCP_device, DID=str_dname)
#                                self.printd("Publishing metadata to {}".format(meta_topic),level=2)
#                                self.mqtt_client.publish(meta_topic,json.dumps(meta,indent=2))
                                meta_topic = self.state_telemetry_topic.format(GWID=self.GCP_device)
                                self.mqtt_client.publish(meta_topic,json.dumps(meta,indent=2))
                    str_gw_meta += ']}'

#                    if self.write_to_file:
                        # Write Gateway metafile
                        # Create gateway device folder in 'misc/{site}/devices'
#                        del gw_meta["pointset"]
#                        del gw_meta["localnet"]
#                        gw_meta["gateway"] = json.loads(str_gw_meta)
#                        gw_meta["system"]["physical_tag"]["asset"]["name"] = str_gwname
#                        gw_meta["cloud"] = {'auth_type': 'RS256'}
#                        device_folder = '{}/devices/{}'.format(site_folder,self.gateway_id)
#                        if not os.path.exists(device_folder):
#                            os.makedirs(device_folder)
#                        metafile = '{}/devices/{}/{}'.format(site_folder,self.gateway_id,METADATA_FILE)
#                        with open (metafile, "w") as outfile:
#                            json.dump(gw_meta, outfile, indent=2)
#                        if self.public_key != '':
#                            rsafile = '{}/devices/{}/{}'.format(site_folder,self.gateway_id,RSA_PUBLIC_FILE)
#                            with open (rsafile, "w") as outfile:
#                                outfile.write(self.public_key)

                except Exception as error:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

                    self.configuration_loaded = False

                    if self.debug > 0:
                        raise Exception("{error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno))
                    else:
                        raise Exception("{error}".format(error=error))

            else:
                self.printd("Not connected to IoT Core - Discovery aborted\n", level=1)
        

def parse_command_line_args():
    #Parse command line arguments
    parser = argparse.ArgumentParser(description=(
            'Delta enteliWEB API based UDMI Discovery Tool for Google Cloud IoT Core.'))
    parser.add_argument("--debug", "-d", help="Debug output level 0,1,2,3,4", default=DEFAULT_DEBUG_LEVEL, const=0, nargs='?', type=int, choices=range(0, 5))
    parser.add_argument("--file", "-f", help="Configuration file to use", default='udmi-config.json')
    parser.add_argument("--meta", "-m", help="Metadata template file to use", default="metatemplate.json")

    return parser.parse_args()

def main():
    args = parse_command_line_args()

    try:
        eWeb = None

        eWeb = UDMIDiscovery(debug=args.debug, configuration_file=args.file, metatemplate=args.meta)
        eWeb.init()
        
        # Start interface should never end
        UDMIDiscovery.run(eWeb)

    except Exception as error:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        if args.debug > 0:
            print("{process} error: {filename}:{line}\n{message}".format(process=INTERFACE_NAME, filename=__file__, message=error, line=exc_tb.tb_lineno))
        else:
            print("{process} error: {filename}\n{message}".format(process=INTERFACE_NAME, filename=__file__, message=error))

if __name__ == '__main__':
    main()
