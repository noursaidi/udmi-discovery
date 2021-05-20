import bntest
import re


class ReadResults(dict):
    """A dictionary of results from a read request, in form {<Property>:<ReadValue>, ...}
    Differs from regular python dictionary in two ways:
    1.  Can be initialized using a cpropertylist.
    2.  [] accessor will search for subproperties.
    """

    def __init__(self, *args, **kw):
        """Initialize ReadResults object.

        @param args: Data to be used set in the dictionary.
                     Can be either a cpropertylist or an existing dictionary.

        """
        if isinstance(args[0], dict):
            # initialize using an existing dictionary
            self.update(args[0])
        else:
            # initialize from properties and values extracted from a cpropertylist
            prop_list = args[0]

            prop_list.rewind()
            obj_ref = prop_list.getreference()

            self.update(self.find_data_in_proplist(obj_ref, prop_list))
            while prop_list.nextproperty() or prop_list.nextobject():
                obj_ref = prop_list.getreference()
                self.update(self.find_data_in_proplist(obj_ref, prop_list))


    def find_data_in_proplist(self, obj_ref, prop_list):
        """Find property names and values from a cpropertylist.
        Should not be called directly, is intended to be used during initialization of a ReadResults object.

        @param obj_ref: Reference to property to be found in the propertylist.
                        The value of this property or all subproperties will be found and added to the dictionary.
        @param prop_list: cpropertylist to use to get object values.
                          Intended to be a cpropertylist used for a OBJECT_READ request.
        """
        ref_depth = obj_ref.getdepth()

        found_data = {}

        if obj_ref.iswholeobjectproperty():
            while prop_list.nextwholeobjectproperty():
                obj_ref = prop_list.getreference()
                found_data.update(self.find_data_in_proplist(obj_ref, prop_list))
        elif obj_ref.isarrayorlistproperty() and obj_ref.getarrayindex() == bntest.WILD_ARRAY_INDEX:
            # Array property - add data for each array index
            count = prop_list.getarraycount(obj_ref)
            if count:
                for array_index in range(1, count + 1):
                    obj_ref.setarrayindex(array_index)
                    prop_list.finditem(obj_ref)
                    found_data.update(self.find_data_in_proplist(obj_ref, prop_list))
            else:
                string_ref = str(obj_ref).lower()
                # remove //SiteName/
                string_ref = string_ref[string_ref.rfind('/') + 1: ].rstrip('[*]')
                status = prop_list.getitemstatus()
                if status == 'OK':
                    found_data[string_ref] = []
                else:
                    found_data[string_ref] = prop_list.getitemstatus()
        elif obj_ref.isgroupproperty():
            # Group property - add data of each subproperty
            obj_ref.changesubpropertydepth(1)
            obj_ref.advancefirstproperty()
            found_data.update(self.find_data_in_proplist(obj_ref, prop_list))
            while obj_ref.advancenextproperty():
                found_data.update(self.find_data_in_proplist(obj_ref, prop_list))
            obj_ref.setdepth(ref_depth)
        elif obj_ref.isunionproperty():
            try:
                # Union property - step into the property
                variant = prop_list.getvariant(obj_ref)
                if variant == 255:
                    string_ref = str(prop_list.getreference()).lower().rstrip('[*]')
                    string_ref = string_ref[string_ref.rfind('/') + 1: ]
                    found_data.update({string_ref: None})
                else:
                    obj_ref.changesubpropertydepth(1)
                    obj_ref.setpropertybyid(variant)
                    found_data.update(self.find_data_in_proplist(obj_ref, prop_list))
                    obj_ref.setdepth(ref_depth)
            except Exception as e:
                # unable to step into property
                status = prop_list.getitemstatus()
                if status != 'OK':
                    string_ref = str(prop_list.getreference()).lower().rstrip('[*]')
                    # remove //SiteName/
                    string_ref = string_ref[string_ref.rfind('/') + 1: ]
                    found_data[string_ref] = status
                else:
                    raise e
        else:
            # Simple property - add this to dictionary
            string_ref = str(obj_ref).lower()

            # remove //SiteName/
            string_ref = string_ref[string_ref.rfind('/') + 1: ]

            list_ref = prop_list.getreference()
            prop_list.finditem(obj_ref)
            status = prop_list.getitemstatus()
            if status == 'OK':
                found_data[string_ref] = prop_list.readitem(obj_ref, bntest.LANGUAGE_ID_ENGLISH)
            else:
                found_data[string_ref] = status
            prop_list.finditem(list_ref)
        return found_data


    def __getitem__(self, key):
        """Allow values to be retrieved using square brackets.

        @param key: The property to be found in the dictionary of read results.
                    If the requested property is found in the dictionary, the corresponding value will be returned.
                    If the property has subproperties, then it will not be a key in the dictionary. In this case, the
                    dictionary will be searched and a ReadResults (dictionary) object of subproperties and values will be returned.
        """
        # return value if key is found in dictionary
        for self_key, self_value in self.items():
            if self_key == key.lower():
                return self_value
        else:
            # create a dictionary of subproperties
            sub_property_dict = {}
            is_list_prop = False
            for key_in_dict, value_in_dict in self.items():
                if key_in_dict.startswith(key.lower() + '.'):
                    sub_property_dict[key_in_dict[len(key) + 1: ]] = value_in_dict

                elif key_in_dict.startswith(key.lower() + '['):
                    # store subvalues with dict key as index so we can find the order
                    is_list_prop = True
                    left_bracket_idx = key_in_dict.find('[', len(key))
                    right_bracket_idx = key_in_dict.find(']', left_bracket_idx)
                    arrayidx = int(key_in_dict[left_bracket_idx + 1 : right_bracket_idx])

                    if len(key_in_dict) - 1 == right_bracket_idx:
                        # add single data entry to array
                        sub_property_dict[arrayidx] = value_in_dict
                    else:
                        sub_prop_start = key_in_dict.find('.', right_bracket_idx) + 1
                        if arrayidx in sub_property_dict.keys():
                            sub_property_dict[arrayidx][key_in_dict[sub_prop_start : ]] = value_in_dict
                        else:
                            sub_property_dict[arrayidx] = {key_in_dict[sub_prop_start : ] : value_in_dict}

            if is_list_prop:
                # return array sorted by array index
                return [sub_property_dict[sorted_key] for sorted_key in sorted(sub_property_dict.keys())]
            if sub_property_dict:
                return ReadResults(sub_property_dict)
            else:
                raise KeyError(key)


    def tryint(self, s):
        """
        Try to return an int, otherwise return a string
        """
        try:
            return int(s)
        except:
            return s


    def alphanum_key(self, s):
        """
        Turn a string into a list of string and number chunks
        "j10p" -> ["j", 10, "p"]
        """
        return [self.tryint(c) for c in re.split('([0-9]+)', s)]


    def sort_nicely(self, list_to_sort):
        """
        Sort the given list in the way that humans expect
        """
        list_to_sort.sort(key = self.alphanum_key)
        return list_to_sort


    def in_order(self, grep=None):
        """Print everything in order (alpabetically)."""
        for key in self.sort_nicely(self.keys()):
            try:
                if (not grep) or (grep in key) or (grep in str(self[key])):
                    print(key + ' : ' + str(self[key]))
            except:
                if (not grep) or (grep in key):
                    print(key + ' : <value not printable>')



class WriteResults(ReadResults):
    """
    A dictionary of properties mapped to statuses.
    """

    def __init__(self, prop_list):
        """Initialize object.

        @param prop_list: cPropertyList containing properties.

        """
        super(WriteResults, self).__init__(prop_list)

        # for any value that is not an error, set this to OK status
        for key, val in self.items():
            if not val or not val.startswith('QERR'):
                self[key] = 'OK'



