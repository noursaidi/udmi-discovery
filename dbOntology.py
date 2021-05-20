# Class to verify compliance Google Digital Buildings Ontology

# Inital version J Brough - 14/05/2021

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
import yaml

class DigitalBuildingsOntology(object):

    entityTypes = {}

    def __init__(self):

        self.resources_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "digitalbuildings","ontology","yaml","resources")

        # scan the folders sequentially for any file names 'GENERALTYPES.yaml' which list the known entities
        # create a single dictionary of all entities types found

        self.entities = []
        for fname in os.listdir(self.resources_path):
            f = os.path.join(self.resources_path, fname)
            if os.path.isdir(f):
                for s_fname in os.listdir(f):
                    if s_fname == 'entity_types':
                        s_f = os.path.join(f, s_fname)
                        if os.path.isdir(s_f):
                            for fl in os.listdir(s_f):
                                if fl == 'GENERALTYPES.yaml':
                                    s_fl = os.path.join(s_f, fl)
                                    with open(s_fl) as y_file:
                                        docs = yaml.load_all(y_file, Loader=yaml.SafeLoader)
                                        for doc in docs:
                                            for k in doc:
                                                self.entities.append(k)
#                                                self.entities[k] = doc[k]

        self.entityTypes = self.entities

    def findEntity (self, strSearch):
        if strSearch in self.entities:
            return self.entities[strSearch]
        else:
            return None


    def checkForEntityType (self, strName):
        found = False
        for entity in self.entities:
            if strName.startswith(entity.lower()):
                found = True
                break
        
        return found

if __name__ == '__main__':
    digitalBuildings = DigitalBuildingsOntology()

