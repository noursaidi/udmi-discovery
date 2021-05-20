from types import *
import re
import datetime
import random
import os

#from . import Results


class BACnetInterface(object):

    def __init__(self, user='Delta', password='Login', site='MainSite'):
        self.server = None
        print("User: {}".format(user))
        print("Pass: {}".format(password))
        print("Site: {}".format(site))
        
        self.user_key = None

        self.site_name = site

    
    def __fill_in_reference(self, reference):
        """Fill in any missing info in a property reference
        Add device if it is not specified
        Add object instance for DEV or DBI if it is not specified
        """
        local_device = 3100000

        # check for missing device
        if not reference.split('.')[0].isdigit():
            reference = str(local_device) + '.' + reference

        # check for missing object instance
        dev, obj, prop = reference.split(".", 2)
        if obj.lower() in ('dev', 'dbi'):
            obj = obj + str(local_device)

        return '.'.join([dev, obj, prop])



    def read(self, property_references):
        """Perform a read and set the results in a dictionary.
        Can read multiple and complex (properties with subproperties) references

        @param References: list of references to read
        @returns: ReadResults dictionary object
        """
        try:
            basestring
        except NameError:
            basestring = str

        if isinstance(property_references, basestring):
            refs = [self.__fill_in_reference(property_references)]
        else:
            refs = [self.__fill_in_reference(ref) for ref in property_references]

        return {"ref": "value"}


    def read_value(self, property_reference):
        """Perform a read of a single property and return value"""
        full_reference = self.__fill_in_reference(property_reference)
        return self.read(full_reference)[full_reference]


    def write(self, data, priority=10, request_type='WRITE'):
        """Send write request.
        Can handle multiple and complex properties.

        @param data: Dictionary of data to be sent in the write request
                     Should be in format: {<Property>:<Value>, ...}
                     <Value> can be a string (for simple properties), a list of strings (for array or list properties),
                     or a dictionary of the same format (for complex properties or properties with subproperties).

                        Examples:
                            Simple Property:         write({'4000.AV1.Name': 'New AV Name'})
                            Array Property:          write({'300.AI4.EventText': ['Text1', 'Text2', 'Text3']})
                            Complex Property:        write({'5000.SCH1.DefaultValue.Real' : '5',
                                                                '5000.SCH1.ExceptionsExt[1]' : {
                                                                    'Schedule[1].Time': '08:00:00.00',
                                                                    'Schedule[1].Value.Real': '5',
                                                                    'Schedule[2].Time': '017:30:00.00',
                                                                    'Schedule[2].Value.Null': '',
                                                                    'Period.CalendarEntry.WeekNDay.Week': '4',
                                                                    'Period.CalendarEntry.WeekNDay.WDay': '5',
                                                                    'Period.CalendarEntry.WeekNDay.Month': '6',
                                                                    'EventPriority': '8',
                                                                            'Description': 'Test Week and Day!'}})
                                            Or this could be written with:
                                                     write({'5000.SCH1.DefaultValue.Real' : '5',
                                                                '5000.SCH1.ExceptionsExt[1]' : {
                                                                'Schedule': [{'Time': '08:00:00.00', 'Value.Real': '5'},
                                                                             {'Time': '017:30:00.00', 'Value.Null': ''}]
                                                                'Period.CalenderEntry.WeekNDay': {
                                                                    'Week': '4',
                                                                    'WDay': '5',
                                                                    'Month': '6'}
                                                                'EventPriority': '8',
                                                                'Description': 'Test Week and Day!' }})
        @param priority: (Optional) write priority
        @param request_type: (Optional) Can be set to OBJECT_CREATE to write data as a create object request.
        @returns: status of property list
        """

        return {"OK"}


    def write_value(self, reference, value):
        """Perform a write for a single property"""
        return self.write({reference : value})

    def find_object_by_name(self, obj_name=None, obj_type=None):
        """
        Given a specific name find the object with that name and return the reference.

        :param obj_name: String the name of the object to find
        :param obj_type: String the acronym of the object to find (blank for any type)
        :return: String the reference or None if not found
        """

        if obj_name is None:
            return None
        if obj_type is None:
            obj_type = ""

        try:

            objReference = bntest.creference()
            wildReference = bntest.cwildreference(self.site_name, int(self.server.sitegetdevicenumber(self.user_key, self.site_name)), bntest.WILD_OBJECT_INSTANCE, obj_type)

            search = bntest.cdescriptorsearch(self.user_key, obj_name, wildReference)

            found = search.first(objReference)
            if found is None:
                return None

            search.complete()

            value = ("{type}{instance}".format(type=objReference.getobjecttypeabbr(bntest.LANGUAGE_ID_ENGLISH), instance=objReference.getobjectinstance()))

        except Exception as error:
            raise Exception("Find Object: {error}".format(error=error))

        return value

if __name__ == '__main__':
    bacnet = BACnetInterface()


