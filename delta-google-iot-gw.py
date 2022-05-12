#!/usr/bin/env python

# delta_google_iot_gw.py
#
# Code for connecting to Google Cloud IoT Core via MQTT, using JWT.
# This will subscribe to the topics defined in a config file and publish
# data as defined in the config file.
# 
# Note: time (including UTC) needs to be set correctly for connection to 
#   Google cloud to work.
#
# V0.0.06 - Revised /devices/[device-id]/commands/# schema
#         Added write protection to Config CSV dictionary
#         Added concept of 'fix_value' for also sending commands from cloud-device via the device config block
#
# V0.0.07 - Revised sleep strategy, if no data is published then do not sleep. Will hasten connection of proxies on startup
#
# V1.0.02 - added signature check for file download
#
# V1.0.03 -> V1.0.05 - revsions to test signatures for downloading new modules
#
# V1.0.06 - added an 'else' term to the do forever loop so that there is a sleep period each scan so as to free up CPU for other processes
#         redefined 'default' state telemetry message + bug fix for when BACnet objects not present in the controller database
#
# V1.0.07 - change MODULE_FILE from hard encoding to use __file__ special python variable
#
# V1.1.0  - Amend Cloud Write to use 'set_value' instead of 'fix_value', allow for reliquish if no 'set_value' present (or Cloud Write is disabled) and allow
#           for a key / value to control the write priority level
#
#
import argparse
import datetime
import logging
import os
import random
import ssl
import time
import json
import shlex
import shutil
import sys
import copy
import requests
import hashlib
import math

import jwt
import paho.mqtt.client as mqtt

import subprocess
from subprocess import Popen, PIPE

# python module imports
from Delta.DeltaEmbedded import BACnetInterface
import bntest
from Delta import Results

# cryptography module imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class bcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m' #Yellow
    FAIL = '\033[91m'
    ENDC = '\033[0m' #White
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    NORMAL = BLUE


def rprint (str_print):
    print(bcolours.RED+str_print+bcolours.NORMAL)

def bprint (str_print):
    print(bcolours.BLUE+str_print+bcolours.NORMAL)

def gprint (str_print):
    print(bcolours.GREEN+str_print+bcolours.NORMAL)

def yprint (str_print):
    print(bcolours.YELLOW+str_print+bcolours.NORMAL)

def cprint (str_print):
    print(bcolours.CYAN+str_print+bcolours.NORMAL)

def pprint (str_print):
    print(bcolours.PURPLE+str_print+bcolours.NORMAL)

ALT_PW = 'Login'
TRUE_LIST =  [1,True,"True","true","TRUE"]
OBJECTS_WITH_PRIORITY_ARRAY = ['AO','AV','BO','BV','MO','MV','CS','LA']
VERSION_INFO = 'GCP IoT Core Gateway : version {}: debug = {}'
INTERFACE_NAME = "Google IoT Gateway"
DETACH_ERROR = 'GATEWAY_DETACHMENT_DEVICE_ERROR'
UDMI_WRITE_COMMAND = 'set_value'
DEFAULT_WRITE_PRIORITY = 9
DEFAULT_TELEMETRY = {"version": 1, "timestamp": "2018-08-26T21:39:29.364Z", "points": {}}
DEFAULT_STATE_TELEMETRY = \
{\
  "version": 1,\
  "timestamp": "<TIME ISO-8601 UTC>",\
  "system": {\
    "make_model": "<BACNET DEV.Model_Name>",\
    "firmware": {\
      "version": "<BACNET DEV.Application_Software_Version>"\
    },\
    "serial_no": "N/A",\
    "operational": "<BACNET DEV.System_Status>"\
  },\
  "pointset": {\
    "points": {}\
  }\
}

DEFAULT_GW_STATE_TELEMETRY = \
{\
  "version": 1,\
  "timestamp": "<TIME ISO-8601 UTC>",\
  "system": {\
    "make_model": "<BACNET DEV.Model_Name>",\
    "firmware": {\
      "version": "<BACNET DEV.Application_Software_Version>"\
    },\
    "serial_no": "<BACNET DEV.Serial_Number>",\
    "last_config": "<BACNET DEV.Last_Restore_Time.dateTime>",\
    "operational": "<BACNET DEV.System_Status>"\
  },\
  "gateway": {\
    "error_ids": []\
  }\
}

LOG_LEVEL_DEFAULT = 0 # The log entry has no assigned severity level.
LOG_LEVEL_DEBUG = 100 # Debug or trace information.
LOG_LEVEL_INFO = 200 # Routine information, such as ongoing status or performance.
LOG_LEVEL_NOTICE = 300 # Normal but significant events, such as start up, shut down, or a configuration change.
LOG_LEVEL_WARNING = 400 # Warning events might cause problems.
LOG_LEVEL_ERROR = 500 # Error events are likely to cause problems.
LOG_LEVEL_CRITICAL = 600 # Critical events cause more severe problems or outages.
LOG_LEVEL_ALERT = 700 # A person must take an action immediately.
LOG_LEVEL_EMERGENCY = 800 # One or more systems are unusable.

logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.CRITICAL)

class GoogleIoTClient():
    MAXIMUM_BACKOFF_TIME = 32
    MQTT_BACKOFF_TIME = 5
    
    CONFIG_CSV_NAME = "Google Cloud IoT Gateway Configuration"
    PUBLIC_KEY_FIL_NAME = "Google Cloud IoT Gateway Public Key"
    GOOGLE_ROOTS_FIL_NAME = "Google Cloud IoT Gateway Roots"
    PRIVATE_KEY_FILE = "rsa_private.pem"
    PUBLIC_KEY_FILE = "rsa_public.pem"
    GOOGLE_ROOTS_FILE = "google_roots.pem"
    GOOGLE_IOT_GATEWAY_FIL_NAME = 'Google IOT Gateway'
    GOOGLE_TELEMETRY_CSV_NAME = 'Google Cloud IoT Telemetry'
    GOOGLE_STATE_TELEMETRY_CSV_NAME = 'Google Cloud IoT State Telemetry'
    GOOGLE_GW_STATE_TELEMETRY_CSV_NAME = 'Google Cloud IoT Gateway State Telemetry'
    DAQ_TELEMETRY_FILE = "telemetry.json"
    DAQ_STATE_TELEMETRY_FILE = "state-telemetry.json"
    DAQ_GW_STATE_TELEMETRY_FILE = "gw-state-telemetry.json"
    MODULE_PERSISTENT_DATA_FILE = "/var/lib/DeltaControls/Files/delta-iot-gw.json"
    MODULE_FILE = os.path.abspath(__file__)

    JWT_EXP_MINS = 20

    def __init__(self, debug=2, site=None, username=None, password=None, RPM=None, log_size=10):
        # Creates the google mqtt client object

        try:
            # 0 off, 1 - Basic, 2 - Normal, 3 = Extra debug, 4 = Full debug
            self.version = '1.1.1'
            self.debug = debug
            self.version_info = VERSION_INFO.format(self.version, self.debug)

            self.configuration = dict()

            self.certificates_dir = None
            self.private_key_path = None
            self.public_key_path = None
            self.google_roots_path = None
            
            # The initial backoff time after a disconnection occurs, in seconds.
            self.minimum_backoff_time = 1

            self.bacnet = None
            self.mqtt_client = None
              
            self.public_key_pem = None

            # Whether to wait with exponential backoff before publishing.
            self.should_backoff = False
            
            self.site = site
            self.username = username
            self.password = password

            self.gateway_id = None

            self.configuration_loaded = False

            self.config_object = None
            self.config_string = None
            self.config_msg = {}
            self.attached_devices = {}
            self.publish_topic_list = []
            self.publish_payload_list = []
            self.publish_state_topic_list = []
            self.publish_state_payload_list = []
            self.RPM = RPM
            self.write_enable = False

            self.telemetry = None
            self.telemetry_object = None
            self.state_telemetry = None
            self.telemetry_topic = '/devices/{{}}/events/pointset'
            self.state_topic = '/devices/{{}}/state'
            self.error_topic = '/devices/{{}}/error'
            self.publish_state_telemetry = False

            self.gw_address = None
            self.gw_state_telemetry = None
            self.gw_state_telemetry_object = None
            self.gw_telemetry_topic = '/devices/{GWID}/events/pointset'
            self.gw_state_topic = '/devices/{GWID}/state'
            self.gw_error_topic = '/devices/{GWID}/error'
            self.gw_bacnetsc_endpoint_res = None
            self.publish_gw_state_telemetry = False

            self.log_size = log_size
            self.error_log = list()
            self.maxupdatems = 1000 # minimum time between cloud messages - default 1 second
            self.poll_interval = 60000 # interval between MQTT publishes - default 1 minute
            self.telemetry_interval = self.poll_interval # Used to space out MQTT publishes - calculed on receipt of gateway config block containing proxy information
            self.telemetry_delay = datetime.datetime.utcnow()

            self.relinquish_always = False

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Google MQTT Constructor"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def get_certificates_path(self):
        # Gets the path on disk where certificates are stored.

        data_path = self.bacnet.server.setupgetstringparameter(self.bacnet.user_key, self.site, "CFG_DATA_DIRECTORY", 0)
        data_path_parts = os.path.split(data_path)
        certificates_path = os.path.join(data_path_parts[0], "Certificates", "Google Cloud MQTT")
        
        if not os.path.exists(certificates_path):
            os.makedirs(certificates_path)
            
        return certificates_path
        
        
    def init(self):
        # Initialize the bacnet interface

        try:
            self.__logError("Starting Google BOS Gateway Version {}".format(self.version_info), level=1)

            try:
                self.bacnet = BACnetInterface(user=self.username, password=self.password, site=self.site)
            except Exception as err:
                self.printd("Login to BACnet Server failed, trying alternate password")
                self.password = ALT_PW
                self.bacnet = BACnetInterface(user=self.username, password=self.password, site=self.site)
            self.__logError(message="BACnet Client Initialised", level=1)
            self.printd("BACnet Client Initialised", level=2)

            bntest.PRIORITY_DEFAULT = DEFAULT_WRITE_PRIORITY

            self.certificates_dir = self.get_certificates_path()
            self.google_roots_path = os.path.join(self.certificates_dir, self.GOOGLE_ROOTS_FILE)
            self.private_key_path = os.path.join(self.certificates_dir, self.PRIVATE_KEY_FILE)
            self.public_key_path = os.path.join(self.certificates_dir, self.PUBLIC_KEY_FILE)
            self.default_google_roots = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Certificates", self.GOOGLE_ROOTS_FILE)
            self.printd("Default google roots path: {path}".format(path=self.default_google_roots), level=3)

            self.__check_private_key()            

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Client creation"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


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


    def printd(self, message, level=2):
        # If debug is on via global DEBUG = True then print messages

        #    :param message:
        #    :param: level: the level of the print statement
        #    :return: nothing

        if self.debug >= level:
            if level == 0:   # Error level
                yprint(message)
            elif level == 1: # Info level
                gprint(message)
            elif level == 2: # Debug level
                cprint(message)
            elif level == 3: # Extra Debug level
                pprint(message)
            elif level == 4: # Test level
                rprint(message)
            else:
                print(message)


    def clear_logs_and_lists(self):
       # Clears out errorLog and device / topic lists
        self.error_log.clear()
        self.attached_devices = {}

    def load_configuration(self):
        #Verifies and loads the configuration file and configures the interface as needed.

        #   :return: Nothing

        try:
            # load config
            self.clear_logs_and_lists()
            self.__logError(message="Searching for Configuration Object", level=3)
            self.printd("Searching for Configuration Object",level=4)
            self.config_object = self.bacnet.find_object_by_name(self.CONFIG_CSV_NAME, "CSV")
            self.__logError(message="Configuration Object={obj}".format(obj=self.config_object), level=4)
            self.printd("Configuration Object={obj}".format(obj=self.config_object), level=1)
            if self.config_object:
                self.config_string = self.bacnet.read_value(self.config_object + ".present_value")
                self.printd("Loading config string: {} ".format(self.config_string), level=1)  
                self.config = json.loads(self.config_string.replace("'",'"'))

                if 'publish-topic' in self.config:
                    self.telemetry_topic = self.config["publish-topic"]
                else:
                    self.telemetry_topic = '/devices/{{}}/events/pointset'
                if 'state-topic' in self.config:
                    self.state_topic = self.config["state-topic"]
                else:
                    self.state_topic = '/devices/{{}}/state'
                if 'maxupdatems' in self.config:
                    self.maxupdatems = self.config["maxupdatems"]
                self.printd('maxupdatems = {}'.format(self.maxupdatems),level=2)
                if 'poll-interval' in self.config:
                    self.poll_interval = self.config["poll-interval"]
                    self.telemetry_interval = self.poll_interval
                self.printd('poll-interval = {}'.format(self.poll_interval),level=2)
                self.gateway_id = self.config["device"]
                if 'rpm' in self.config:
                    self.RPM = True if self.config["rpm"] in TRUE_LIST else False
                if 'cloud-write' in self.config:
                    self.write_enable = True if self.config["cloud-write"] in TRUE_LIST else False
                self.printd("Cloud Writeback = {}".format(self.write_enable),level=1)
                if 'write-priority' in self.config:
                    wp = self.config["write-priority"]
                    if not isinstance(wp, str) and (1 <= wp <=16):
                        bntest.PRIORITY_DEFAULT = wp
                    else:
                        self.__logError(message="Invalid Write Priority ({}) in config".format(wp), level=1)
                self.printd("Cloud Write Priority = {}".format(bntest.PRIORITY_DEFAULT),level=1)
                if 'relinquish-always' in self.config:
                    self.relinquish_always = True if self.config["relinquish-always"] in TRUE_LIST else False
                self.printd("Cloud Always Relinquishes on NULL = {}".format(self.relinquish_always),level=1)
                if 'jwt_exp_mins' in self.config:
                    self.JWT_EXP_MINS = self.config["jwt_exp_mins"]
                if 'debug' in self.config:
                    self.debug = self.config["debug"]
                    self.version_info = VERSION_INFO.format(self.version, self.debug)

                google_roots_object = self.bacnet.find_object_by_name(self.GOOGLE_ROOTS_FIL_NAME, "FIL")
                if not google_roots_object is None:
                    # Found FIL object for Google Roots file, check if it is later than the one currently in use
                    fil_google_roots_file = self.bacnet.read_value(google_roots_object + ".file_data.diskpath")
                    fil_file = os.stat(fil_google_roots_file)
                    fil_file_time_date = fil_file.st_mtime
                    roots_file = os.stat(self.google_roots_path)
                    roots_file_time_date = roots_file.st_mtime
                    if fil_file_time_date > roots_file_time_date:
                        # Google Roots update - copy the new file into the cert folder
                        self.printd("Copying Google roots {} to {}".format(fil_google_roots_file, self.google_roots_path), level=1)
                        shutil.copyfile(fil_google_roots_file, self.google_roots_path)
                        self.printd("Google roots {} copied to {}".format(fil_google_roots_file, self.google_roots_path), level=1)
                        self.printd("Clearing out old keys", level=1)
                        self.__logError(message="Clearing out old keys", level=3)
                        os.remove(self.private_key_path)
                        os.remove(self.public_key_path)
                        self.__check_private_key()

                self.telemetry_object = self.bacnet.find_object_by_name(self.GOOGLE_TELEMETRY_CSV_NAME, "CSV")
                if self.telemetry_object:
                    self.printd("Using telemetry from {}".format(self.telemetry_object), level=1)
                    telemetry_string = self.bacnet.read_value(self.telemetry_object + ".present_value")
                    self.printd("Loading telemetry string: {} ".format(telemetry_string), level=1)  
                    self.telemetry = json.loads(telemetry_string)
                elif os.path.exists(self.DAQ_TELEMETRY_FILE):
                    # Use default from file
                    self.printd("Using telemetry from {}".format(self.DAQ_TELEMETRY_FILE), level=1)
                    with open(self.DAQ_TELEMETRY_FILE) as json_file:  
                        self.telemetry = json.load(json_file)
                else:
                    self.printd("Using preset telemetry", level=1)
                    self.telemetry = DEFAULT_TELEMETRY
                self.printd("Telemetry = {}".format(self.telemetry), level=4)

                self.state_telemetry_object = self.bacnet.find_object_by_name(self.GOOGLE_STATE_TELEMETRY_CSV_NAME, "CSV")
                if self.state_telemetry_object:
                    self.printd("Using state telemetry from {}".format(self.state_telemetry_object), level=1)
                    state_telemetry_string = self.bacnet.read_value(self.state_telemetry_object + ".present_value")
                    self.printd("Loading state telemetry string: {} ".format(state_telemetry_string), level=1)  
                    self.state_telemetry = json.loads(state_telemetry_string)
                elif os.path.exists(self.DAQ_STATE_TELEMETRY_FILE):
                    # Use default from file
                    self.printd("Using state telemetry from {}".format(self.DAQ_STATE_TELEMETRY_FILE), level=1)
                    with open(self.DAQ_STATE_TELEMETRY_FILE) as json_file:  
                        self.state_telemetry = json.load(json_file)
                else:
                    self.printd("Using preset state telemetry", level=1)
                    self.state_telemetry = DEFAULT_STATE_TELEMETRY
                self.printd("State Telemetry = {}".format(self.state_telemetry), level=4)

                self.gw_state_telemetry_object = self.bacnet.find_object_by_name(self.GOOGLE_GW_STATE_TELEMETRY_CSV_NAME, "CSV")
                if self.gw_state_telemetry_object:
                    self.printd("Using Gateway state telemetry from {}".format(self.gw_state_telemetry_object), level=1)
                    state_telemetry_string = self.bacnet.read_value(self.gw_state_telemetry_object + ".present_value")
                    self.printd("Loading Gateway state telemetry string: {} ".format(state_telemetry_string), level=1)  
                    self.gw_state_telemetry = json.loads(state_telemetry_string)
                elif os.path.exists(self.DAQ_GW_STATE_TELEMETRY_FILE):
                    # Use default from file
                    self.printd("Using Gateway state telemetry from {}".format(self.DAQ_GW_STATE_TELEMETRY_FILE), level=1)
                    with open(self.DAQ_GW_STATE_TELEMETRY_FILE) as json_file:  
                        self.gw_state_telemetry = json.load(json_file)
                else:
                    self.printd("Using preset Gateway state telemetry", level=1)
                    self.gw_state_telemetry = DEFAULT_GW_STATE_TELEMETRY
                self.printd("Gateway State Telemetry = {}".format(self.gw_state_telemetry), level=4)

                self.configuration_loaded = True

            else:
                self.printd("Config CSV Object {} not found".format(self.CONFIG_CSV_NAME), level=1)
                self.configuration_loaded = False

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            self.configuration_loaded = False

            user_error = "Config CSV Object load"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{error}".format(error=error))



    def configuration_changed(self):
        # Check to see if there are configuration changes. 

        #   :return: boolean: True configuration file changed, False configuration file did not change

        result = False

        if not self.configuration_loaded:
            self.printd("self.configuration = False",level=2)
            return True
            
        if  self.mqtt_client is None:
            self.printd("self.mqtt_client = False",level=2)
            return True
            
        try:
            config_object = self.bacnet.find_object_by_name(self.CONFIG_CSV_NAME, "CSV")
            if config_object != self.config_object:
                self.printd("Config object changed: {} <> {}".format(config_object, self.config_object), level=1)
                result = True
            else: 
                config_string = self.bacnet.read_value(self.config_object + ".present_value")
                if config_string != self.config_string:
                    self.printd("Config string changed. {} String <old> <new>: <{}> <{}>".format(self.config_object, self.config_string, config_string), level=1)
                    self.config_string = config_string
                    result = True

            gw_state_object = self.bacnet.find_object_by_name(self.GOOGLE_GW_STATE_TELEMETRY_CSV_NAME, "CSV")
            if gw_state_object:
                if gw_state_object != self.gw_state_telemetry_object:
                    self.printd("Gateway State Telemetry object changed: {} <> {}".format(gw_state_object, self.gw_state_telemetry_object), level=1)
                    result = True
                else: 
                    gw_state_string = json.loads(self.bacnet.read_value(self.gw_state_telemetry_object + ".present_value"))
                    if gw_state_string != self.gw_state_telemetry:
                        self.printd("Gateway State Telemetry changed. {} String <old> <new>: <{}> <{}>".format(self.gw_state_telemetry_object, self.gw_state_telemetry, gw_state_string), level=1)
                        self.gw_state_telemetry = gw_state_string
                        result = True

            state_object = self.bacnet.find_object_by_name(self.GOOGLE_STATE_TELEMETRY_CSV_NAME, "CSV")
            if state_object:
                if state_object != self.state_telemetry_object:
                    self.printd("State Telemetry object changed: {} <> {}".format(state_object, self.gw_state_telemetry_object), level=1)
                    result = True
                else: 
                    state_string = json.loads(self.bacnet.read_value(self.state_telemetry_object + ".present_value"))
                    if state_string != self.state_telemetry:
                        self.printd("State Telemetry changed. {} String <old> <new>: <{}> <{}>".format(self.state_telemetry_object, self.state_telemetry, state_string), level=1)
                        self.state_telemetry = state_string
                        result = True

            #read the google roots from FIL and update file if changed
            google_roots_object = self.bacnet.find_object_by_name(self.GOOGLE_ROOTS_FIL_NAME, "FIL")
            if google_roots_object:
                # Found FIL object for Google Roots file, check if it is later than the one currently in use
                fil_google_roots_file = self.bacnet.read_value(google_roots_object + ".file_data.diskpath")
                fil_file = os.stat(fil_google_roots_file)
                fil_file_time_date = fil_file.st_mtime
                roots_file = os.stat(self.google_roots_path)
                roots_file_time_date = roots_file.st_mtime
                if fil_file_time_date > roots_file_time_date:
                    # Google Roots update - copy the new file into the cert folder
                    self.printd("Google Roots Updated",level=1)
                    self.__logError(message="Google roots updated", level=3)
                    result = True

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Configuration change check"
            self.__logError(message="{} Error".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))

        return result


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


    def process_gateway_message(self, topic_type, message_dict):
        try:
            self.printd("Received Gateway {} topic {}".format(self.gateway_id, topic_type), level=2)
            message_str = json.dumps(message_dict)
            if topic_type == 'errors' :
                self.__logError(message="MQTT ERROR MESSAGE from : <{}> : <{}>".format(self.gateway_id,message_str), level=1)
                if message_dict['error_type'] == DETACH_ERROR :
                    device_id = message_dict['device_id']
                    self.printd('Device {} detached from Gateway {} - reattaching'.format(device_id, self.gateway_id),level=2)
                    self.attached_devices[device_id] = False
                    self.attach_device(device_id, '')
                else:
                    self.printd ('Gateway {} Error occured - {}'.format(self.gateway_id, message_str),level=2)
            elif topic_type == 'config' :
                self.config_msg  = message_dict
                self.attached_devices = {}
                if "gateway" in self.config_msg:
                    if "proxy_ids" in self.config_msg["gateway"]:
                        for proxy_id in self.config_msg["gateway"]["proxy_ids"] :
                            pointset_topic = self.telemetry_topic.replace('{{}}', proxy_id)
                            if not pointset_topic in self.publish_topic_list:
                                # new device - add it to the lists
                                self.printd('Adding proxy device {} to lists = {}'.format(proxy_id, pointset_topic),level=2)
                                self.publish_topic_list.append (pointset_topic)
                                self.publish_payload_list.append (self.telemetry)
                            else:
                                # device is already in the lists
                                self.printd('proxy id {} already subscribed'.format(proxy_id),level=2)
                            state_topic = self.state_topic.replace('{{}}', proxy_id)
                            if not state_topic in self.publish_state_topic_list:
                                # new device - add it to the state lists
                                self.printd('Adding proxy device {} to state lists = {}'.format(proxy_id, state_topic),level=2)
                                self.publish_state_topic_list.append (state_topic)
                                self.publish_state_payload_list.append (self.state_telemetry)
                            else:
                                # device is already in the state lists
                                self.printd('proxy id {} already subscribed to state list'.format(proxy_id),level=2)

                        # Check to see if a device has been removed, if so NULL the entries
                        rescan = False
                        for proxy_topic in self.publish_topic_list:
                            str_split = proxy_topic.split('/')
                            if not str_split[2] in self.config_msg["gateway"]["proxy_ids"]:
                                self.printd('Blanking proxy device {} from lists'.format(str_split[2]),level=2)
                                ix = self.publish_topic_list.index(proxy_topic)
                                self.publish_topic_list[ix] = None
                                self.publish_payload_list[ix] = None
                                self.publish_state_topic_list[ix] = None
                                self.publish_state_payload_list[ix] = None
                                rescan = True
                        # Clean up behind
                        while rescan == True:
                            self.printd('Cleaning up deleted proxies from lists',level=2)
                            rescan = False # Prepare to finish
                            ix = 0
                            abort = False
                            while (ix < len(self.publish_topic_list)) and (abort == False):
                                if self.publish_topic_list[ix] == None:
                                    self.printd('Removing proxy device # {} from lists'.format(ix),level=2)
                                    rescan = True # Don't finish yet
                                    self.publish_topic_list.pop(ix)
                                    self.publish_payload_list.pop(ix)
                                    self.publish_state_topic_list.pop(ix)
                                    self.publish_state_payload_list.pop(ix)
                                    abort = True # Abort this scan and go again
                                ix += 1
                        self.printd('{}'.format(self.publish_topic_list),level=4)
                        self.printd('{}'.format(self.publish_state_topic_list),level=4)

                        # Calculate the interval between proxy telemetry
                        proxy_count = len(self.publish_payload_list)
                        if proxy_count > 0:
                            tm_per_proxy = self.poll_interval / proxy_count
                        else:
                            tm_per_proxy = self.poll_interval
                        if tm_per_proxy < (self.maxupdatems * 2):
                            # Not enoungh time allowed in config - need to stretch
                            tm_per_proxy = proxy_count * (self.maxupdatems * 2) # self.maxupdatems gives time between mqqt publishes - double it here to allow for overhead
                        self.telemetry_interval = tm_per_proxy # in milliseconds
                        self.printd('telemetry_interval = {}'.format(self.telemetry_interval),level=2)

                # Check for any pointset metadata
                if "pointset" in self.config_msg:
                    if "points" in self.config_msg["pointset"]:
                        pt = self.config_msg["pointset"]["points"]
                        if "bacnetsc_endpoint" in pt:
                            if UDMI_WRITE_COMMAND in pt["bacnetsc_endpoint"]:
                                current_url = self.bacnet.read_value("NP9.SC_Primary_Hub_URI")
                                if current_url != pt["bacnetsc_endpoint"][UDMI_WRITE_COMMAND]:
                                    self.__logError("New Secure Connect URL Received",level=1)
                                    str_val = pt["bacnetsc_endpoint"][UDMI_WRITE_COMMAND]
                                    wpm = {}
                                    wpm = {"NP9.SC_Primary_Hub_URI" : str_val}
                                    res = self.bacnet.write(wpm)
                                    self.gw_bacnetsc_endpoint_res = res
                                    if 'OK' in json.dumps(res):
                                        self.gw_state_telemetry["pointset"]["points"] = {"bacnetsc_endpoint": {"value_state": "applied"}}
                                    else:
                                        self.gw_state_telemetry["pointset"]["points"] = {"bacnetsc_endpoint": {"value_state": "failed", "status": res}}
                                    self.__logError("Applying Network Changes",level=1)
                                    self.apply_network_changes()
                                else:
                                    self.printd("Secure Connect URL Matches",level=4)
                                    self.gw_state_telemetry["pointset"]["points"] = {"bacnetsc_endpoint": {"value_state": "applied"}}

                self.publish_gw_state_telemetry = True
                self.publish_gateway_device_state (self.gateway_id)

                if "system" in self.config_msg:
                    if "networks" in self.config_msg["system"]:
                        if "bacnet" in self.config_msg["system"]["networks"]:
                            if "address" in self.config_msg["system"]["networks"]["bacnet"]:
                                self.gw_address = self.config_msg["system"]["networks"]["bacnet"]["address"]
                    if "blobs" in self.config_msg["system"]:
                        if "connector" in self.config_msg["system"]["blobs"]:
                            if "download_url" in self.config_msg["system"]["blobs"]["connector"] and "install_hash" in self.config_msg["system"]["blobs"]["connector"]:
                                # Check to see if this is a new download source or hash checksum and if so download the new module
                                try:
                                    self.printd("Received config system blob: {}".format(self.config_msg["system"]["blobs"]["connector"]),level=4)
                                    download_url = self.config_msg["system"]["blobs"]["connector"]["download_url"]
                                    install_hash = self.config_msg["system"]["blobs"]["connector"]["install_hash"]
                                    module_json = {}
                                    current_url = ""
                                    current_hash = ""
                                    download = True
                                    if os.path.exists(self.MODULE_PERSISTENT_DATA_FILE):
                                        try:
                                            with open(self.MODULE_PERSISTENT_DATA_FILE) as json_file:  
                                                module_json = json.load(json_file)
                                            json_file.close()
                                            self.printd("Checking current file record: {}".format(module_json),level=4)
                                            if "download_url" in module_json:
                                                current_url = module_json["download_url"]
                                            if "install_hash" in module_json:
                                                current_hash = module_json["install_hash"]
                                            if current_url == download_url and current_hash == install_hash:
                                                download = False

                                        except Exception as error:
                                            self.printd("Error with persistent file", level = 1)

                                    if download:
                                        # New file to download (or we have no record of downloading so assume we must)
                                        if self.load_module_from_url(loader_file=self.MODULE_FILE,loader_repo=download_url,file_signature=install_hash) == True:
                                            # Success so update persistent datafile and exit to force a restart of the python script
                                            module_json["download_url"] = download_url
                                            module_json["install_hash"] = install_hash
                                            self.printd("Updating file {} with {}".format(self.MODULE_PERSISTENT_DATA_FILE,module_json),level=4)
                                            with open(self.MODULE_PERSISTENT_DATA_FILE, "w") as json_wr_file:  
                                                json.dump(module_json, json_wr_file)
                                            json_wr_file.close()
                                            os._exit(0)
 
                                except Exception as error:
                                    err_tpc = self.gw_error_topic.replace('{GWID}',self.gateway_id)
                                    err_msg = 'Error processing gateway config block ({})'.format(self.config_msg["system"]["blobs"]["connector"])
                                    self.__publishError(err_tpc, err_msg)

            elif topic_type == 'commands':
                self.printd("Recieved Gateway Command - {}".format(message_str), level=2)
                if "load_module" in message_dict and "loader_repo" in message_dict and "signature" in message_dict:
                    if self.load_module_from_url(loader_file=message_dict["load_module"], loader_repo=message_dict["loader_repo"],file_signature=message_dict["signature"]) == True:
                        # Success so exit to force a restart of the python script
                        os._exit(0)
                elif "restore_module" in message_dict:
                    backup_file = '{}.bak'.format(message_dict["restore-module"])
                    loader_file = message_dict["restore-module"]
                    if os.path.exists(backup_file):
                        self.__logError(message="Restoring backup {} to {}".format(backup_file,loader_file),level = 0)
                        if os.path.exists(loader_file):
                            os.remove(loader_file)
                        os.rename(backup_file,loader_file)
                        if os.path.exists(self.MODULE_PERSISTENT_DATA_FILE):
                            os.remove(self.MODULE_PERSISTENT_DATA_FILE)
                        os._exit(0)
                    else:
                        self.__logError(message="No backup ({}) to restore".format(backup_file),level = 0)
                elif "restart_module" in message_dict:
                    os._exit(0)
                elif "reboot" in message_dict:
                    os.system('reboot now')
                elif "write_property" in message_dict:
                    str_val = json.dumps(message_dict["write-property"])
                    self.printd("Command = {}".format(str_val),level=4)
                    wpm = str_val
                    self.printd('wpm = {}'.format(wpm),level=1)
                    res = self.bacnet.write(json.loads(wpm),priority=bntest.PRIORITY_DEFAULT)
                    self.__logError('Cloud->Device message {}'.format(wpm), level=0)
                elif "activate_network_change" in message_dict:
                    self.apply_network_changes()
                elif "clear_module_register" in message_dict:
                    if os.path.exists(self.MODULE_PERSISTENT_DATA_FILE):
                        os.remove(self.MODULE_PERSISTENT_DATA_FILE)
                        self.__logError(message="Cleared OTA Module Register",level = 0)
                    else:
                        self.__logError(message="No OTA Module Registered",level = 0)
                    
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error processing Gateway Message"
            err_tpc = self.gw_error_topic.replace('{GWID}',self.gateway_id)
            err_msg = '{}: ({})'.format(user_error, message_dict)
            self.__publishError(err_tpc, err_msg)

            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def getHashKey(self, data_path, output_path):
        if not os.path.exists(data_path):
            self.printd("Cannot generate hash.  File does not exist = {}".format(data_path),level=4)
            return False
            
        sha256_hash = hashlib.sha256()
        with open(data_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        f = open(output_path, "w")
        f.write(sha256_hash.hexdigest())
        f.close()
        return True

    def validate_signature(self, image_file_path, file_signature):
        """
        Validate Signed Image using public key and image.signature
        """
        target_dir  = "/usr/tmp"
        HASH_KEY_FILE = "hash.key"
        IMAGE_SIGNATURE = "image.signature"
        IMAGE_BINARY_SIGNATURE = "image_binary.signature"
        DLM_PUBLIC_KEY_FILE = "dlm_public.pem"
        
        self.printd("Validating image {} with signature {}".format(image_file_path, file_signature),level=3)
        result = False
       
        # Generate the hash key        
        hash_file_path = os.path.join(target_dir, HASH_KEY_FILE)
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        self.printd("Generating Hash Key {}...".format(hash_file_path), level=4)
        if not self.getHashKey(image_file_path, hash_file_path):
            return result

        signature_binary_file_path = os.path.join(target_dir, IMAGE_BINARY_SIGNATURE)
        self.printd("Signature binary file: {}".format(signature_binary_file_path), level=4)
        
        # write the given signature to a file
        signature_file_path = os.path.join(target_dir, IMAGE_SIGNATURE)
        f = open(signature_file_path, "w")
        
        # put a newline on the signature so the base64 decode works
        f.write(file_signature + "\n")
        f.close()  
       
        # Convert image signature back to digital form
        signature_args = ["openssl", "base64", "-d", "-in", signature_file_path, "-out", signature_binary_file_path]
        digital_result = subprocess.run(signature_args, stdout=PIPE, stderr=PIPE)
        digital_result.check_returncode()

        # Validate image with signature
        public_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Certificates", DLM_PUBLIC_KEY_FILE)
        sign_args = ["openssl", "dgst", "-sha256", "-verify", public_key_path, "-signature", signature_binary_file_path, hash_file_path]
        self.printd("sign_args = {}".format(sign_args),level=3)
        verify_result = subprocess.run(sign_args, stdout=PIPE, stderr=PIPE)
        verify_result.check_returncode()

        # Remove the hash, signatures
        os.remove(signature_file_path)
        os.remove(signature_binary_file_path)
        os.remove(hash_file_path)

        if not verify_result:
            self.printd("Image is invalid!", level=1)
            return result
        
        self.printd("Image is valid!", level=3)
        # Validation pass, set result to true
        result = True 
        return result


    def load_module_from_url (self, loader_file, loader_repo, file_signature):
        try:
            backup_file = '{}.bak'.format(loader_file)
            hash_file = '{}.hash'.format(loader_file)
            self.__logError(message="Downloading {} to {}".format(loader_repo, hash_file),level = 0)
            r = requests.get (loader_repo, allow_redirects=True)
            open(hash_file, 'wb').write(r.content)
            abort_dl = True
            if file_signature != None:
                if self.validate_signature(hash_file, file_signature):
                    abort_dl = False

            if abort_dl:
                self.__logError(message="Validation Error - download aborted",level=0)
                return False
            else:            
                self.__logError(message="Backing up {} to {}".format(loader_file, backup_file),level = 0)
                if os.path.exists(backup_file):
                    self.__logError(message="Deleting old Backup {}".format(backup_file),level = 0)
                    os.remove(backup_file)
                if os.path.exists(loader_file):
                    self.__logError(message="Renaming old version to ...bak {}".format(backup_file),level = 0)
                    os.rename(loader_file, backup_file)
                os.rename(hash_file,loader_file)
                self.__logError(message="Download complete",level = 0)
                return True
        
        except:
            err_tpc = self.gw_error_topic.replace('{GWID}',self.gateway_id)
            err_msg = 'Error loading python module - aborting'
            self.__publishError(err_tpc, err_msg)
            return False


    def apply_network_changes(self):
        # Applies changes made to NP objects

        device = self.bacnet.server.setupgetparameter(self.bacnet.user_key, self.site, "CFG_SITE_DEVICENUMBER", 0)
        ref = bntest.creference(self.site, device)
        self.bacnet.server.reinitializedevice(self.bacnet.user_key, ref, bntest.REINITDEV_ACTIVATECHANGES)


    def process_proxy_device_message(self, proxy_device, topic_type, message_dict):
        try:
            self.__logError("Received Proxy '{}' topic".format(topic_type), level=3)
            if topic_type == 'config' or topic_type == 'commands':
                # Find which proxy this is for and match to pub_topic_list index
                length = len(self.publish_topic_list)
                tp_pos = 0
                while tp_pos < length :
                    if proxy_device in self.publish_topic_list[tp_pos] :
                        break
                    tp_pos += 1
                json_state = message_dict

                if topic_type == 'config':
                    json_state.update({"timestamp" : "YYYY-MM-DDTHH:MM:SSUTC"})
                    self.publish_payload_list [tp_pos] = json_state
                    # Parse device config block to see if there are any 'fix_value' dictionary entries
                    bn_addr = self.__get_bacnet_address(proxy_device, json_state)
                    for pt in json_state["pointset"]["points"]:
                        found_fix = True if self.relinquish_always else False
                        pt_dict = json_state["pointset"]["points"][pt]
                        bn_ref = self.publish_payload_list[tp_pos]['pointset']["points"][pt]["ref"]
                        pt_type = bn_ref.split('.')
                        if pt_type[0][:2] in OBJECTS_WITH_PRIORITY_ARRAY:
                            str_val = None
                            if UDMI_WRITE_COMMAND in pt_dict:
                                st_msg = {}
                                st_msg["category"] = "device.write.telemetry"
                                st_msg["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                if self.write_enable:
                                    str_val = pt_dict[UDMI_WRITE_COMMAND]
                                    if self.__isfloat(str(str_val)):
                                        str_val = '{:.2f}'.format(float(str_val))
                                    else:
                                        str_val = '"{}"'.format(str(str_val))
                                    found_fix = True
                                else:
                                    self.__logError(message="Cloud Write disabled", level=1)
                                    str_val = None
                                    st_msg["message"] = 'cloud write forbidden'
                                    st_msg["level"] = LOG_LEVEL_CRITICAL
                                    json_state['pointset']['points'][pt]['value_state'] = "failure"
                                    json_state['pointset']['points'][pt]['status'] = st_msg
                                    found_fix = False # Do not write
                            else:
                                if 'pointset' in self.publish_state_payload_list[tp_pos]:
                                    if 'points' in self.publish_state_payload_list[tp_pos]['pointset']:
                                        if pt in self.publish_state_payload_list[tp_pos]['pointset']['points']:
                                            if 'value_state' in self.publish_state_payload_list[tp_pos]['pointset']['points'][pt] \
                                            or 'status' in self.publish_state_payload_list[tp_pos]['pointset']['points'][pt]:
                                                found_fix = True
                            if found_fix:
                                bn = bn_addr + bn_ref
                                res = self.bacnet.write({bn: str_val}, priority=bntest.PRIORITY_DEFAULT)
                                self.printd("Cloud Write Back: {}".format(res),level=1)
                                for v in res.values():
                                    if v == 'OK':
                                        if str_val == None:
                                            ret = json_state['pointset']['points'][pt].pop('value_state', None)
                                        else:
                                            json_state['pointset']['points'][pt]['value_state'] = "applied"
                                        ret = json_state['pointset']['points'][pt].pop("status", None)
                                    else:
                                        json_state['pointset']['points'][pt]['value_state'] = "failure"
                                        st_msg["message"] = v
                                        st_msg["level"] = LOG_LEVEL_ERROR
                                        json_state['pointset']['points'][pt]['status'] = st_msg
                                self.__logError(message="BACnet Write {} to {}: status = {}".format(str_val,bn,res), level=1)

                    # Now update the state payload publish list to remember any 'status' messages
                    self.publish_state_payload_list[tp_pos] = json_state
                    self.printd('Publishing state data for {}'.format(proxy_device),level=3)
                    if self.RPM == True:
                        published = self.publish_proxy_device_data_rpm (proxy_device, tp_pos)
                    else:
                        published = self.publish_proxy_device_data (proxy_device, tp_pos)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error processing proxy device message"
            err_tpc = self.error_topic.replace('{{}}',proxy_device)
            err_msg = '{}: {}'.format(user_error, message_dict)
            self.__publishError(err_tpc, err_msg)

            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))


    def publish_proxy_device_data (self, proxy_device_id, publish_ix):
        try:
            ret_val = False
            device_topic = self.publish_topic_list[publish_ix]
            json_payload = self.publish_payload_list[publish_ix]
            state_topic = self.publish_state_topic_list[publish_ix]
            bn_addr = self.__get_bacnet_address(proxy_device_id, json_payload)

            telemetry_json = copy.deepcopy(self.telemetry)
            state_json = self.__replace_tags( copy.deepcopy(self.state_telemetry), bn_addr)
            if "pointset" in json_payload.keys():
                if "points" in json_payload["pointset"].keys():
                    state_points = {}
                    points = {}
                    for bn_prop in json_payload["pointset"]["points"]:
                        bn_ref = json_payload["pointset"]["points"][bn_prop]
                        state_points[bn_prop] = {}
                        if 'status' in bn_ref:
                            state_points[bn_prop]["status"] = bn_ref["status"]
                        if 'value_state' in bn_ref:
                            state_points[bn_prop]["value_state"] = bn_ref["value_state"]
                        if "ref" in bn_ref:
                            # parse the BACnet reference to make sure it uses '_' not '-' in Property Names
                            str_bn = bn_ref["ref"].lower()
                            str_split = str_bn.split('.')
                            str_bn = bn_addr + str_split[0] + '.' + str_split[1].replace('-','_')

                            try:
                                bn_res = self.__bacnet_read_value(str_bn)    # Use DeltaEmbedded funtion for RP single
                                if self.__isJSON(bn_res):
                                    js_val = {"present_value": bn_res}
                                    points[bn_prop] = js_val
                                else:
                                    if self.__isfloat(bn_res):
                                        try:
                                            if math.isnan(float(bn_res)):
                                                str_val = '"present_value": "nan"'
                                            else:
                                                str_val = '"present_value": {:.2f}'.format(float(bn_res))
                                        except:
                                            str_val = '"present_value": "nan"'
                                    else:
                                        str_val = '"present_value": "{}"'.format(bn_res)
                                    points[bn_prop] = json.loads('{'+str_val+'}')

                            except Exception as error:
                                self.printd("BACnet RP Error Occurred - {}".format(error),level=1)
                                state_points[bn_prop]["status"] = {}
                                state_points[bn_prop]["status"]["message"] = '{}'.format(error)
                                state_points[bn_prop]["status"]["category"] = "device.read.telemetry"
                                state_points[bn_prop]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                state_points[bn_prop]["status"]["level"] = LOG_LEVEL_ERROR
                                continue

                        else:
                            state_points[bn_prop]["status"] = {}
                            state_points[bn_prop]["status"]["message"] = "Bad 'ref'"
                            state_points[bn_prop]["status"]["category"] = "device.config.validate"
                            state_points[bn_prop]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                            state_points[bn_prop]["status"]["level"] = LOG_LEVEL_ERROR

                    state_json["pointset"]["points"] = state_points
                    self.printd("state_json = {}".format(state_json),level=4)
                    telemetry_json["points"] = points
                    self.printd("telemetry_json = {}".format(telemetry_json),level=4)
                    # Publish to MQTT
                    str_payload = json.dumps(telemetry_json)
                    if self.debug <= 3:
                        self.__logError('Publishing telemetry to {}'.format(device_topic), level=3)
                    else:
                        self.__logError('Publishing message {} to {}'.format(str_payload, device_topic), level=4)
                    self.mqtt_client.publish (device_topic, '{}'.format(str_payload), qos=1)
                    str_payload = json.dumps(state_json)
                    self.mqtt_client.publish (state_topic, '{}'.format(str_payload), qos=1)
                    ret_val = True
                    return ret_val

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error publishing proxy device data message"
            err_tpc = self.error_topic.replace('{{}}',proxy_device_id)
            err_msg = '{}: ({} to {})'.format(user_error, self.publish_payload_list[publish_ix], self.publish_topic_list[publish_ix])
            self.__publishError(err_tpc, err_msg)
            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            return ret_val


    def publish_proxy_device_data_rpm (self, proxy_device_id, publish_ix):
        # equivalent function to publish_proxy_device_data (self, proxy_device_id, publish_ix)
        # Using Read Property Multiple

        try:
            ret_val = False
            device_topic = self.publish_topic_list[publish_ix]
            json_payload = self.publish_payload_list[publish_ix]
            state_topic = self.publish_state_topic_list[publish_ix]
            bn_addr = self.__get_bacnet_address(proxy_device_id, json_payload)

            # Assemble the RPM request
            pt_nm = []
            bn_rpm = []
            telemetry_json = copy.deepcopy(self.telemetry)
            state_json = self.__replace_tags(copy.deepcopy(self.state_telemetry), bn_addr)
            if "pointset" in json_payload.keys():
                if "points" in json_payload["pointset"].keys():
                    state_points = {}
                    points = {}
                    for bn_prop in json_payload["pointset"]["points"]:
                        pt_nm.append(bn_prop)
                        bn_ref = json_payload["pointset"]["points"][bn_prop]
                        state_points[bn_prop] = {}
                        if 'status' in bn_ref:
                            state_points[bn_prop]["status"] = bn_ref["status"]
                        if 'value_state' in bn_ref:
                            state_points[bn_prop]["value_state"] = bn_ref["value_state"]
                        if 'ref' in bn_ref:
                            # parse the BACnet reference to make sure it uses '_' not '-' in Property Names
                            str_bn = bn_ref["ref"].lower()
                            str_split = str_bn.split('.')
                            str_bn = bn_addr + str_split[0] + '.' + str_split[1].replace('-','_')
                            bn_rpm.append(str_bn)
                        else:
                            state_points[bn_prop]["status"] = {}
                            state_points[bn_prop]["status"]["message"] = "Bad 'ref'"
                            state_points[bn_prop]["status"]["category"] = "device.config.validate"
                            state_points[bn_prop]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                            state_points[bn_prop]["status"]["level"] = LOG_LEVEL_ERROR

                    # BACnet Read Property Multiple
                    if not bn_rpm:
                        state_points["system"]["statuses"]["message"] = "Empty Pointset"
                        state_points["system"]["statuses"]["category"] = "device.state.com"
                        state_points["system"]["statuses"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        state_points["system"]["statuses"]["level"] = LOG_LEVEL_WARNING
                        self.__logError('{} Empty Pointset - publish aborted'.format(proxy_device_id),level=3)
                        self.printd('{} Empty Pointset - publish aborted'.format(proxy_device_id), level=2)
                    else:
                        self.__logError('Read Property Multiple = {}'.format(bn_rpm),level=4)
                        try:
                            bn_err = False
                            bn_res = self.__bacnet_read(bn_rpm) # Use local function to better handle ReadPropertMultiple
                            self.printd('bn_res = {}'.format(bn_res),level=4)
                        except Exception as error:
                            self.printd("BACnet RPM Error Occurred - {}".format(error),level=4)
                            bn_err = True
                            for bn_prop in pt_nm:
                                state_points[bn_prop]["status"] = {}
                                state_points[bn_prop]["status"]["message"] = '{}'.format(error)
                                state_points[bn_prop]["status"]["category"] = "device.read.telemetry"
                                state_points[bn_prop]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                state_points[bn_prop]["status"]["level"] = LOG_LEVEL_ERROR

                        if not bn_err:
                            # Process the results
                            ix = 0
                            points = {}
                            for bn_prop in bn_res:
                                try:
                                    str_val = (bn_res[bn_prop])
                                    if self.__isfloat(bn_res[bn_prop]):
                                        try:
                                            if math.isnan(float(bn_res[bn_prop])):
                                                str_val = '"present_value": "nan"'
                                            else:
                                                str_val = '"present_value": {:.2f}'.format(float(bn_res[bn_prop]))
                                        except:
                                            str_val = '"present_value": "nan"'
                                        finally:
                                            points[pt_nm[ix]] = json.loads('{'+str_val+'}')
                                    elif self.__isJSON(bn_res[bn_prop]):
                                        js_val = {"present_value": bn_res[bn_prop]}
                                        points[pt_nm[ix]] = js_val
                                    elif not ('QERR_CODE' in str_val):
                                        str_val = '"present_value": "{}"'.format(bn_res[bn_prop])
                                        points[pt_nm[ix]] = json.loads('{'+str_val+'}')
                                    else:
                                        state_points[pt_nm[ix]]["status"] = {}
                                        state_points[pt_nm[ix]]["status"]["message"] = '{}'.format(str_val)
                                        state_points[pt_nm[ix]]["status"]["category"] = "device.read.telemetry"
                                        state_points[pt_nm[ix]]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                        state_points[pt_nm[ix]]["status"]["level"] = LOG_LEVEL_ERROR
                                    ix += 1
                                except Exception as error:
                                    self.printd("Error {} with {} occurred - {}".format(error, bn_res[bn[prop]]),level=1)
                                    state_points[pt_nm[ix]]["status"] = {}
                                    state_points[pt_nm[ix]]["status"]["message"] = '{}'.format(str_val)
                                    state_points[pt_nm[ix]]["status"]["category"] = "device.read.telemetry" ##
                                    state_points[pt_nm[ix]]["status"]["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                                    state_points[pt_nm[ix]]["status"]["level"] = LOG_LEVEL_CRITICAL
                                    continue
                        else:
                            self.printd("No RPM Results to process",level=4)

                        state_json["pointset"]["points"] = state_points
                        self.printd("state_json = {}".format(state_json),level=4)
                        telemetry_json["points"] = points
                        self.printd("telemetry_json = {}".format(telemetry_json),level=4)
                        # Publish to MQTT
                        str_payload = json.dumps(telemetry_json)
                        self.printd('Publishing RPM telemetry to {}'.format(device_topic), level=2)
                        if self.debug <= 3:
                            self.__logError('Publishing RPM telemetry to {}'.format(device_topic), level=3)
                        else:
                            self.__logError('Publishing RPM message {} to {}'.format(str_payload, device_topic), level=4)
                        self.mqtt_client.publish (device_topic, '{}'.format(str_payload), qos=1)
                        str_payload = json.dumps(state_json)
                        self.printd('Publishing state telemetry to {}'.format(state_topic), level=2)
                        self.mqtt_client.publish (state_topic, '{}'.format(str_payload), qos=1)
                        ret_val = True
                        return ret_val

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error publishing proxy device data rpm message"
            err_tpc = self.error_topic.replace('{{}}',proxy_device_id)
            err_msg = '{}: ({} to {})'.format(user_error, self.publish_payload_list[publish_ix], self.publish_topic_list[publish_ix])
            self.__publishError(err_tpc, err_msg)

            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            return ret_val


    def publish_gateway_device_state (self, gateway_device_id):
        try:
            device_topic = self.gw_state_topic.replace('{GWID}',gateway_device_id)
            json_payload = self.gw_state_telemetry
            state_json = self.__replace_tags(copy.deepcopy(json_payload))
            str_payload = json.dumps(state_json)
            self.__logError('Publishing message to {}'.format(device_topic), level=3)
            self.printd ('Publishing message {} to {}'.format(str_payload, device_topic), level=4)
            self.mqtt_client.publish (device_topic, '{}'.format(str_payload), qos=1)
            self.publish_gw_state_telemetry = False

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Error publishing gateway state message"
            err_tpc = self.gw_error_topic.replace('{GWID}',self.gateway_id)
            err_msg = '{}: ({})'.format(user_error, self.gw_state_telemetry)
            self.__publishError(err_tpc, err_msg)
            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)


    def __isJSON(self, str):
        try:
            is_json = json.loads(str)
            return True
        except ValueError:
            return False


    def __isfloat(self, num):
        try:
            float(num)
            return True
        except ValueError:
            return False


    def __get_bacnet_address(self, proxy_id, json_payload):
        try:
            bn_addr = ''
            if 'localnet' in json_payload.keys():
                if 'subsystem' in json_payload['localnet'].keys():
                    ss = 'subsystem'
                elif 'subsystems' in json_payload['localnet'].keys():
                    ss = 'subsystems'
                else:
                    ss = ''
                if ss != '':
                    if 'bacnet' in json_payload['localnet'][ss].keys():
                        if 'local_id' in json_payload['localnet'][ss]['bacnet'].keys():
                            str_addr = json_payload['localnet'][ss]['bacnet']['local_id']
                            if '0x' in str_addr:
                                bn_addr = str(int(str_addr,16))
                            else:
                                bn_addr = str_addr
            elif 'system' in json_payload.keys():
                if 'network' in json_payload['system'].keys():
                    ss = 'network'
                elif 'networkds' in json_payload['system'].keys():
                    ss = 'networkds'
                else:
                    ss = ''
                if ss != '':
                    if 'bacnet' in json_payload['system'][ss].keys():
                        if 'address' in json_payload['system'][ss]['bacnet'].keys():
                            str_addr = json_payload['system'][ss]['bacnet']['address']
                            if '0x' in str_addr:
                                bn_addr = str(int(str_addr,16))
                            else:
                                bn_addr = str_addr

            if bn_addr != '':
                bn_addr += '.'
        
            return bn_addr

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

            user_error = "Invalid JSON for 'local_id'"
            err_tpc = self.error_topic.replace('{{}}',proxy_id)
            self.__publishError(err_tpc, user_error)
            self.__logError(message="{}".format(user_error), filename=filename, linenumber=exc_tb.tb_lineno, level=1)
            if self.debug > 0:
                raise Exception("{user}: {error} - {file}:{line}".format(user=user_error, error=error, file=filename, line=exc_tb.tb_lineno))
            else:
                raise Exception("{user}".format(user=user_error))



    def detach_device(self, device_id):
        #Detach the device from the gateway.
        # [START detach_device]
        detach_topic = '/devices/{}/detach'.format(device_id)
        print('Detaching: {}'.format(detach_topic))
        self.mqtt_client.publish(detach_topic, '{}', qos=1) # publish the detach request immediately
        time.sleep(self.MQTT_BACKOFF_TIME)
        # [END detach_device]


    def attach_device(self, device_id, auth):
        # Attach the device to the gateway.
        # [START attach_device]
        attach_topic = '/devices/{}/attach'.format(device_id)
        attach_payload = '{{"authorization" : "{}"}}'.format(auth)
        self.mqtt_client.publish(attach_topic, attach_payload, qos=1) # publish the attach request immediately
        self.__logError(message="MQTT Publish {} : {}".format(attach_topic,attach_payload), level=4)
        time.sleep(self.MQTT_BACKOFF_TIME)
        # [END attach_device]


    def mqtt_error_str(self, rc):
        # Convert a Paho error to a human readable string.
        return '{}: {}'.format(rc, iot.error_string(rc))


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
        mqtt_config_topic = '/devices/{}/config'.format(self.gateway_id)
        self.printd('Subscribing to {}'.format(mqtt_config_topic), level=4)
        client.subscribe(mqtt_config_topic, qos=1)

        # Subscribe to the commands topic, QoS 1 enables message acknowledgement.
        mqtt_command_topic = '/devices/{}/commands/#'.format(self.gateway_id)
        self.printd('Subscribing to {}'.format(mqtt_command_topic), level=4)
        client.subscribe(mqtt_command_topic, qos=0)

        # The topic gateways receive error updates on. QoS must be 0.
        error_topic = '/devices/{}/errors'.format(self.gateway_id)
        self.printd ('Subscribing to {}'.format(error_topic), level=4)
        client.subscribe(error_topic, qos=0)


    def on_disconnect(self, unused_client, unused_userdata, rc):
        # Paho callback for when a device disconnects.
        user_error = 'Google mqtt: on_disconnect', self.mqtt.mqtt_error_str(rc) 
        self.printd(user_error, level=0)

        # Since a disconnect occurred, the next loop iteration will wait with
        # exponential backoff.
        self.should_backoff = True


    def on_publish(self, unused_client, unused_userdata, mid):
        # Paho callback when a message is sent to the broker.
        pass


    def on_message(self, unused_client, unused_userdata, message):
        # Callback when the device receives a message on a subscription
        try:
            message_str = message.payload.decode('utf-8')
            message_dict = json.loads(message.payload)
            self.printd("Google MQTT MESSAGE received topic: <{topic}>   message: <{message}>".format(topic=message.topic, message=str(message_dict)), level=4)
            self.__logError(message="MQTT MESSAGE from : <{topic}>".format(topic=message.topic), level=4)
            sp_topic = message.topic.split('/')
            if sp_topic[2] == self.gateway_id:
                self.process_gateway_message(sp_topic[3], message_dict)
            elif sp_topic[2] in self.config_msg['gateway']['proxy_ids']:
                self.process_proxy_device_message(sp_topic[2], sp_topic[3], message_dict)

        except Exception as error:
            payload = str(message.payload)
            err_tpc = self.gw_error_topic.replace('{GWID}',self.gateway_id)
            err_msg = 'Error: {} - Incorrectly formatted received message <{}> on topic <{}> with Qos {}'.format(error, payload, message.topic, str(message.qos))
            self.__publishError(err_tpc, err_msg)
            self.printd(err_msg, level=1)


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


    def __bacnet_read(self, property_references):
        # Perform a read and set the results in a dictionary.
        # Can read multiple and complex (properties with subproperties) references

        # @param References: list of references to read
        # @returns: ReadResults dictionary object

        try:
            basestring
        except NameError:
            basestring = str

        if isinstance(property_references, basestring):
            refs = [self.__fill_in_reference(property_references)]
        else:
            refs = [self.__fill_in_reference(ref) for ref in property_references]

        prop_list = bntest.cpropertylist()
        obj_ref = bntest.creference()

        for ref in refs:
            obj_ref.parsereference(
                    '//{site}/{obj_and_prop}'.format(site=self.bacnet.site_name, obj_and_prop=ref),
                    bntest.LANGUAGE_ID_ENGLISH,
                    self.bacnet.user_key)
            prop_list.addreference(obj_ref)

        self.bacnet.server.executeobjectrequest(self.bacnet.user_key, bntest.OBJECT_READ, prop_list)

        status = prop_list.getpropertyliststatus()
        if status != 'OK' and not ('partial_failure' in status.lower()):
            raise RuntimeError(status)

        return Results.ReadResults(prop_list)


    def __bacnet_read_value(self, property_reference):
        """Perform a read of a single property and return value"""
        full_reference = self.__fill_in_reference(property_reference)
        return self.__bacnet_read(full_reference)[full_reference]


    def __fill_in_reference(self, reference):
        # Fill in any missing info in a property reference
        # Add device if it is not specified
        # Add object instance for DEV or DBI if it is not specified

        local_device = self.bacnet.server.setupgetparameter(self.bacnet.user_key, self.bacnet.site_name, "CFG_SITE_DEVICENUMBER", 0)

        # check for missing device
        if not reference.split('.')[0].isdigit():
            reference = str(local_device) + '.' + reference

        # check for missing object instance
        dev, obj, prop = reference.split(".", 2)
        if obj.lower() in ('dev', 'dbi'):
            obj = obj + str(local_device)

        return '.'.join([dev, obj, prop])


    def __get_bacnet_value(self, reference):
        return self.__bacnet_read_value(reference)


    def __get_time_value(self, time_format="%Y-%m-%d %H:%M:%S", mode="UTC"):

        # :param time_format: name of format, or text containing strftime format specifiers
        # :param mode: "UTC" or "Local"
        # :return: formatted time string

        if time_format == "ISO-8601":
            if mode.lower() == "utc":
                return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                return datetime.datetime.now().isoformat()
        else:
            if mode.lower() == "utc":
                return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                return datetime.datetime.now().strftime(time_format)


    def __replace_tags(self, data_obj, proxy_addr = ''):
        # Recursively explore data_obj and replace any tags found with corresponding data

        # :param data_obj:
        #         structure consisting of nested dictionaries and lists, with text data
        #         tags to replace are contain function and 0 or more parameters separated with spaces:
        #                 <TAG_NAME param1 param2 ...>
        # :return:
        #         copy of data_obj with all tags replaced

        try:
            basestring
        except NameError:
            basestring = str

        if isinstance(data_obj, dict):
            return {self.__replace_tags(k,proxy_addr): self.__replace_tags(v,proxy_addr) for k, v in data_obj.items()}
        elif isinstance(data_obj, list):
            return [self.__replace_tags(d, proxy_addr) for d in data_obj]
        elif isinstance(data_obj, basestring):
            if data_obj.startswith("<") and data_obj.endswith(">"):
                # split on spaces that are not contained within quotes
                data_split = shlex.split(data_obj[1:-1])
                tag_function = data_split[0]
                # call specific function for this tag
                if tag_function.lower() == "bacnet":
                    if proxy_addr == '':
                        tag_parameters = data_split[1:]
                    else:
                        tag_parameters = []
                        for tag in data_split[1:]:
                            obj, prop = tag.split(".")
                            if obj.lower() in ('dev', 'dbi'):
                                obj = obj + proxy_addr
                                tag = proxy_addr + obj + prop
                            tag_parameters.append(tag)

                    try:
                        res = self.__get_bacnet_value(*tag_parameters)
                        if 'DEV.System_Status' in tag_parameters:
                            if res.lower() in ['operational_read_only','download_in_progress','backup_in_progress']:
                                res = False
                            else:
                                res = True
                        return res
                    except:
                        # unable to read - leave tag as is
                        return data_obj
                elif tag_function.lower() == "time":
                    tag_parameters = data_split[1:]
                    return self.__get_time_value(*tag_parameters)
            else:
                # no tag - no change required
                return data_obj
        else:
            # unexpected - return so that value is not changed
            return data_obj


JOHN    def __publishError(self, topic, message):
        self.printd("{}".format(message), level=1)
        self.__logError("{}".format(message), level=1)
        self.mqtt_client.publish(topic, '{}'.format(message), qos=1)


    def db_synchronize(self):
        try:
            # write the public key to FIL
            public_key_object = self.bacnet.find_object_by_name(self.PUBLIC_KEY_FIL_NAME, "FIL")
            if public_key_object:
                # update file_data.diskpath property of FIL object
                fil_pem = self.bacnet.read_value(public_key_object + ".file_data.diskpath")
                str_split = fil_pem.split('/')
                fil_public_key_pem = ''
                for ix in range(len(str_split)-1):
                    fil_public_key_pem += '{}/'.format(str_split[ix])
                fil_public_key_pem += self.PUBLIC_KEY_FILE
                bn_wr = json.loads('{"' + public_key_object + '.file_data.diskpath": "' + fil_public_key_pem + '"}')
                self.bacnet.write(bn_wr)
                if os.path.exists(self.public_key_path):
                    file = open(self.public_key_path, "r")
                    self.public_key_pem = file.read()
                    file.close()
                else:
                    self.printd("Not Found {}".format(self.public_key_path),level=4)
                    if self.public_key_pem is None:
                        # generate the pem from the private key
                        self.printd('self.public_key_pem = {}'.format(self.public_key_pem),level=1)
                        with open(self.private_key_path, "rb") as key_file:
                            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                        public_key = private_key.public_key()
                        temp_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        self.public_key_pem = temp_pem.decode('utf-8')
                        fil_public_key_pem = self.bacnet.read_value(public_key_object + ".file_data.diskpath")
                        file = open(self.public_key_path, "wb")
                        file.write(temp_pem)
                        file.close()
                        self.__logError(message="Public key created", level=2)
                        self.printd("Writing Public Key to {}".format(public_key_object),level=4)
                        shutil.copy (self.public_key_path, fil_public_key_pem)

                self.bacnet.write({public_key_object + ".Description": self.public_key_pem})
            else:
                # Public Key FIL Object not found - clear out old Public Key data
                self.public_key_pem = None
                if os.path.exists(self.public_key_path):
                    os.remove(self.public_key_path)

            # Now check to see if the Module FIL Object exists, if it does write the .diskpath and version number
            google_iot_gw_object = self.bacnet.find_object_by_name(self.GOOGLE_IOT_GATEWAY_FIL_NAME, "FIL")
            if google_iot_gw_object:
                self.bacnet.write({google_iot_gw_object + ".Description": self.version_info})

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.__logError(message="Update DB Error", filename=filename, linenumber=exc_tb.tb_lineno, level=1)


    def run(self):
        # Connects a device, sends data, and receives data
        # [START iot_mqtt_run]
        print("\n----------\nStarting {interface}\n----------\n".format(interface=INTERFACE_NAME))

        # load initial config
        try:
            self.load_configuration()
            self.__logError("Configuration loaded", level=2)

        except Exception as error:
            self.printd("Configuration load error {err}".format(err=error), level=1)
            self.__logError(message="Configuration loading error: {}".format(error), level=1)

        if self.configuration_loaded:
            try:
                self.printd("self.configuration_loaded; Connecting to MQTT",level=2)
                self.__logError(message="self.configuration_loaded; Connecting to MQTT", level=1)
                jwt_iat = datetime.datetime.utcnow()
                self.mqtt_client = self.get_mqtt_client(
                    self.config["project"], self.config["location"], self.config["registry"],
                    self.gateway_id, self.private_key_path, "RS256",
                    self.google_roots_path, self.config["hostName"], self.config["tcpPort"])

            except Exception as error:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

                self.printd("get_mqtt_client({},{},{},{},{},{},{},{},{}) failed".format( \
                    self.config["project"], self.config["location"], self.config["registry"], \
                    self.gateway_id, self.private_key_path, "RS256", \
                    self.google_roots_path, self.config["hostName"], self.config["tcpPort"]),level=4)
                self.printd("Error connecting:", level = 2)
                self.__logError("Error connecting:", level = 2)
                self.__logError(message="Error connecting", filename=filename, linenumber=exc_tb.tb_lineno, level=1)
        
        publish_ix = 0
        published = False
        
        # Loop forever
        while True:
            try:
                self.db_synchronize()

            except Exception as error:
                self.printd("DB synchronize error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                self.__logError(message="DB Synchronize error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                continue

            try:
                config_changed =  self.configuration_changed()

            except Exception as error:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                self.printd("Checking Configuration changed error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                self.__logError(message="Checking Configuration changed error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                continue
            
            if config_changed:
                try:
                    self.printd("Config changed load config", level=1)
                    self.load_configuration()
                    self.printd("New configuration loaded", level=1)
                    self.__logError("New configuration loaded", level=2)
                    self.telemetry_delay = datetime.datetime.utcnow()

                except Exception as error:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.printd("Configuration load error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                    self.__logError(message="Configuration load error: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                    continue

                try:
                    if self.configuration_loaded:
                        self.printd("config_changed; Connecting to MQTT",level=2)
                        self.attached_devices = {}
                        jwt_iat = datetime.datetime.utcnow()

                        if self.mqtt_client:
                            self.mqtt_client.disconnect()
                            time.sleep(self.MQTT_BACKOFF_TIME)

                        self.mqtt_client = self.get_mqtt_client(
                            self.config["project"], self.config["location"], self.config["registry"],
                            self.gateway_id, self.private_key_path, "RS256",
                            self.google_roots_path, self.config["hostName"], self.config["tcpPort"])

                except Exception as error:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.printd("Error connecting to MQTT: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                    self.__logError(message="Error connecting to MQTT: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                    continue

            # Wait if backoff is required.
            if self.configuration_loaded and self.should_backoff:
                #  wait and connect again.
                delay = self.minimum_backoff_time + random.randint(0, 1000) / 1000.0
                self.printd('Waiting for {} before reconnecting.'.format(delay), level=2)
                time.sleep(delay)
                if self.minimum_backoff_time < self.MAXIMUM_BACKOFF_TIME:
                    self.minimum_backoff_time *= 2
                try:
                    if self.config:
                        self.printd("self.should_backoff; Connecting to MQTT",level=2)
                        self.mqtt_client = self.get_mqtt_client(
                            self.config["project"], self.config["location"], self.config["registry"],
                            self.gateway_id, self.private_key_path, "RS256",
                            self.google_roots_path, self.config["hostName"], self.config["tcpPort"])
                        time.sleep(self.MQTT_BACKOFF_TIME)

                except Exception as error:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.printd("Error connecting to MQTT after backoff: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                    self.__logError(message="Error connecting to MQTT after backoff: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                    continue

            # [START iot_mqtt_jwt_refresh]
            if self.configuration_loaded:
                seconds_since_issue = (datetime.datetime.utcnow() - jwt_iat).seconds
                if (seconds_since_issue > 60 * self.JWT_EXP_MINS):
                    try:
                        self.printd("JWT Expired; Connecting to MQTT",level=2)
                        self.printd(('Refreshing token after {}s').format(seconds_since_issue), level=2)
                        jwt_iat = datetime.datetime.utcnow()
                        self.telemetry_delay = jwt_iat
                        self.attached_devices = {}
                        self.mqtt_client.disconnect()
                        self.mqtt_client = self.get_mqtt_client(
                            self.config["project"], self.config["location"], self.config["registry"], 
                            self.gateway_id, self.private_key_path, "RS256", 
                            self.google_roots_path, self.config["hostName"], self.config["tcpPort"])
                        self.telemetry_delay = datetime.datetime.utcnow()

                    except Exception as error:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        self.printd("Error connecting to MQTT after JWT refresh: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                        self.__logError(message="Error connecting to MQTT after JWT refresh: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level=1)
                        continue

            if datetime.datetime.utcnow() > self.telemetry_delay:
                # Publish "payloads" to the MQTT topic.
                if len(self.publish_payload_list) > 0:
                    try:
                        device_topic = self.publish_topic_list[publish_ix]
                        str_split = self.publish_topic_list[publish_ix].split('/')
                        proxy_device_id = str_split[2]
                        if proxy_device_id not in self.attached_devices:
                            self.printd("Attaching device {}".format(proxy_device_id),level=4)
                            self.attach_device(proxy_device_id, '')
                            self.printd("Attached device {}".format(proxy_device_id),level=4)
                            proxy_config_topic = '/devices/{}/config'.format(proxy_device_id)
                            self.printd('Subscribing to {}'.format(proxy_config_topic), level=4)
                            self.mqtt_client.subscribe(proxy_config_topic,qos=1)

                            # Subscribe to the commands topic, QoS 1 enables message acknowledgement.
                            proxy_command_topic = '/devices/{}/commands/#'.format(proxy_device_id)
                            self.printd('Subscribing to {}'.format(proxy_command_topic), level=4)
                            self.mqtt_client.subscribe(proxy_command_topic, qos=0)
                            self.attached_devices[proxy_device_id] = True

                        self.printd('Publishing state data for {} - {}'.format(proxy_device_id,publish_ix),level=4)
                        if self.RPM == True:
                            published = self.publish_proxy_device_data_rpm (proxy_device_id, publish_ix)
                        else:
                            published = self.publish_proxy_device_data (proxy_device_id, publish_ix)

                        publish_ix += 1
                        if publish_ix >= len(self.publish_payload_list):
                            publish_ix = 0

                    except Exception as error:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

                        user_error = "Error publishing to proxy device"
                        err_tpc = self.error_topic.replace('{{}}',proxy_device_id)
                        err_msg = '{}'.format(user_error)
                        self.__publishError(err_tpc, err_msg)

                        self.printd("Error publishing: {error} - {file}:{line}".format(error=error, file=filename, line=exc_tb.tb_lineno), level = 2)
                        self.__logError(message="Error publishing", error=error, level=1)
                        continue

                # Schedule next publish
                self.telemetry_delay = datetime.datetime.utcnow()+datetime.timedelta(milliseconds=self.telemetry_interval)
                self.printd("Going Dark for {} secs until {}".format(self.telemetry_interval/1000, self.telemetry_delay),level=3)


def parse_command_line_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=(
            'Delta Google Cloud IoT Core MQTT device connection code.'))
    parser.add_argument("--debug", "-d", help="Debug output level 0,1,2,3,4", default=2, const=2, nargs='?', type=int, choices=range(0, 5))
    parser.add_argument("--site", "-s", help="Site to use", default='MainSite')
    parser.add_argument("--name", "-n", help="Python user name to login to bnserver", default='Delta')
    parser.add_argument("--password", "-p", help="Python password to login to bnserver", default='Thi#s1sTh3N%wLo1n')
    parser.add_argument("--rpm", "-m", help="Use Read Property Multiple", default=True)
    parser.add_argument("--log", "-l", help="Error log size in number of entries", default=25, const=25, nargs='?', type=int, choices=range(0, 100))

    return parser.parse_args()

def main():
    args = parse_command_line_args()

    try:
        gwObject = None

#        gwObject = GoogleIoTClient(debug=args.debug, debugTiming=args.timetest, site=args.site,
#                                              username=args.name, password=args.password,
#                                              configuration_file=args.file, mapping_file=args.mapping,
#                                              log_size=args.log)
        gwObject = GoogleIoTClient(debug=args.debug, site=args.site,
                                              username=args.name, password=args.password,
                                              RPM=args.rpm, log_size=args.log)

        gwObject.init()
        # Start interface should never end
        gwObject.run()

    except Exception as error:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        if args.debug > 0:
            print("{process} error: {filename}:{line}\n{message}".format(process=INTERFACE_NAME, filename=__file__, message=error, line=exc_tb.tb_lineno))
        else:
            print("{process} error: {filename}\n{message}".format(process=INTERFACE_NAME, filename=__file__, message=error))

if __name__ == '__main__':
    main()
