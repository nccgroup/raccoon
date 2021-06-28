#!/usr/bin/env python3

"""
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Jerome Smith @exploresecurity (with thanks to Viktor Gazdag @wucpi)

https://www.github.com/nccgroup/raccoon

Released under AGPL - refer to LICENSE for more information.
"""

import sys
import requests
from xml.etree import ElementTree
import json
from urllib.parse import urlencode
import traceback
from operator import itemgetter

#################
### Constants ###

VERSION = '1.0'

CONFIG_FILE_FORMAT = '''\
    {
        "hostname": "somewhere.my.salesforce.com",
        "username": "",
        "password": "",
        "token": "",
        "objects": ["Account", "Contact"],
        "checkLimits": true,
        "debug": 0
    }'''

API_VERSION = '51.0'

# Supported sharing models
# TODO look into others e.g. "ControlledByCampaign":"Controlled By Campaign", "ControlledByLeadOrContact":"Controlled By Lead Or Contact" - less likely to be used by critical objects though
# Refs: https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_field_types.htm, https://help.salesforce.com/articleView?id=sharing_model_fields.htm&type=5
SHARING_VALUE_TO_LABEL = {"Private":"Private", "Read":"Public Read Only", "ReadWrite":"Public Read/Write", "ReadWriteTransfer":"Public Read/Write/Transfer", "FullAccess":"Public Full Access", "ControlledByParent":"Controlled by Parent"}

# Known 'gotchas': keys are object lowercase names, singular and plural
UNSUPPORTED_OBJECTS = {'activity': '\'Activity\' is not an independent object - choose e.g. Task or Event instead', 'activities': '\'Activity\' is not an independent object - choose e.g. Task or Event instead', 'user': '\'User\' is unsupported as other settings that uniquely affect access to users are currently not considered', 'users': '\'User\' is unsupported as other settings that uniquely affect access to users are currently not considered', 'attachment': '\'Attachment\' sharing is largely govered by access to its parent record: ensure parent objects are specified in the config file', 'attachments': '\'Attachment\' sharing is largely govered by access to its parent record: ensure parent objects are specified in the config file', 'file': '\'File\' is unsupported as it uses a different sharing model that is not currently considered', 'files': '\'File\' is unsupported as it uses a different sharing model that is not currently considered'}

###############
### Globals ###

total_reqs = 0

###############
### Classes ###

class RaccoonError(ValueError):
    """A more specific Exception class to raise"""
    pass

#################
### Functions ###

def banner():
    """Introduce yourself."""
    print("Raccoon - Salesforce object access auditor")
    print("- version " + VERSION)
    print("- https://www.github.com/nccgroup/raccoon")
    print("* Refer to README for usage notes including important limitations *")

def error(message, exception, debug=0):
    """Handle errors with increasing amounts of output depending on 'debug' level, then exit.
    
    Arguments:
        debug -- 0 for a simple message, 1 to add exception details, 2 to output stack trace to .err file
    """
    print("\nERROR: " + message)
    print("  '" + type(exception).__name__ + "' was raised")
    if debug > 0:
        print("  - with " + str(len(exception.args)) + " argument(s):")
        for i, a in enumerate(exception.args):
            print("  [" + str(i+1) + "] " + str(a))
    if debug > 1:
        try:
            with open(sys.argv[0] + '.v' + VERSION + '.err', 'w') as error_file:
                traceback.print_exc(file=error_file)
        except:
            print("  ERROR: Failed to write stack trace to file")
            traceback.print_exc()
        else:
            print("  Stack trace written to " + sys.argv[0] + '.v' + VERSION + ".err")
    if debug < 2:
        print("To find out more, try increasing the debug level in the config file")
    exit(1)

def load_config(file):
    """Load configuration from a file so that credentials are not in the user's console history."""
    with open(file) as config_file:
        config = json.load(config_file)
    if 'hostname' in config:
        hostname = config['hostname']
        # Deal with possibility that a URL has been supplied
        if 'http' in hostname:
            hostname = hostname.split('/')[2]
        if 'lightning.force.com' in hostname:
            hostname = hostname.split('.')[0] + '.my.salesforce.com'
    else:
        raise ValueError("No 'hostname' parameter in config file " + file)
    if 'username' in config:
        username = config['username']
    else:
        raise ValueError("No 'username' parameter in config file " + file)
    if 'password' in config:
        password = config['password']
    else:
        raise ValueError("No 'password' parameter in config file " + file)
    # token not always required
    if 'token' in config:
        token = config['token']
    else:
        token = ''
    if 'objects' in config:
        objects = config['objects']
    else:
        raise ValueError("No 'objects' array in config file " + file)
    # do not insist on checkLimits: just make the default True
    if 'checkLimits' in config:
        check_limits = config['checkLimits']
    else:
        check_limits = True
    # debug is optional
    if 'debug' in config:
        try:
            debug = int(config['debug'])
        except:
            raise TypeError("Debug value should be a number")
    else:
        debug = 0
    return (hostname, username, password, token, objects, check_limits, debug)

def call_rest_api(rest_api_url, session_id=None):
    """Call the REST API with a supplied URL and optional authentication."""
    if session_id is None:
        rest_headers = None
    else:
        rest_headers = {'Authorization': 'Bearer ' + session_id, 'Sforce-Query-Options': 'batchSize=2000'}
    global total_reqs
    total_reqs += 1
    response = requests.get(rest_api_url, headers=rest_headers)
    # Check for unsuccessful response
    response.raise_for_status()
    json_response = json.loads(response.text)
    return json_response

def call_rest_query_api(rest_query_api_url, session_id, query=None):
    """Call the REST Query API, taking into account possible recursion due to pagination of results."""
    if query is None:
        # then we are paging through results
        request_url = rest_query_api_url
    else:
        # it's a fresh request
        request_url = rest_query_api_url + '/?' + urlencode({"q": query})
    json_response = call_rest_api(request_url, session_id)
    records = json_response['records']
    if 'nextRecordsUrl' in json_response:
        next_records_url = 'https://' + rest_query_api_url.split('/')[2] + json_response['nextRecordsUrl']
        next_records = call_rest_query_api(next_records_url, session_id)
        records.extend(next_records)
    return records

def call_soap_api(soap_api_url, body, soap_action, session_id=None):
    """Call the SOAP API with a supplied URL and optional authentication."""
    xml_declaration = '<?xml version="1.0" encoding="utf-8"?>'
    if session_id is None:
        soap_header = ""
    else:
        soap_header = '''
        <soapenv:Header>
            <tns:SessionHeader>
                <tns:sessionId>''' + session_id + '''</tns:sessionId>
            </tns:SessionHeader>
        </soapenv:Header>
        '''
    envelope = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://soap.sforce.com/2006/04/metadata">' + soap_header + body + '</soapenv:Envelope>'
    soap_message = xml_declaration + envelope
    http_headers = {'Content-Type': 'text/xml', 'SOAPAction': soap_action}
    global total_reqs
    total_reqs += 1
    response = requests.post(soap_api_url, data=soap_message, headers=http_headers)
    # Check for unsuccessful response - but not via raise_for_status() to get more debug info
    if response.status_code != 200:
        raise requests.HTTPError("Expected 200 response: got " + str(response.status_code), response.text)
    root = ElementTree.fromstring(response.text)
    return root

def call_read_metadata(metadata_url, session_id, type_, fullnames):
    """Call readMetadata()."""
    body = '''
        <soapenv:Body>
            <tns:readMetadata>
                <tns:type>''' + type_ + '''</tns:type>
                <tns:fullNames>''' + fullnames + '''</tns:fullNames>
            </tns:readMetadata>
        </soapenv:Body>
        '''
    read_metadata_response_element = call_soap_api(metadata_url, body, '""', session_id).find('.//{http://soap.sforce.com/2006/04/metadata}readMetadataResponse')
    if read_metadata_response_element is None:
        raise RaccoonError("No readMetadata response for " + type_ + "/" + fullnames)
    return read_metadata_response_element

def check_api_ver_supported(rest_api_url):
    """Check that the API version is supported by the host but, if not, don't fail."""
    supported_api_vers = call_rest_api(rest_api_url)
    # Simple substring check will suffice
    if API_VERSION not in json.dumps(supported_api_vers):
        print("Unsupported API version - this tool requires version " + API_VERSION)
        print("- let's carry on anyway but this could explain any subsequent errors")

def login(hostname, username, password, token):
    """Log in to get a session ID and the metadata URL."""
    body = '''
        <soapenv:Body>
          <n1:login xmlns:n1="urn:partner.soap.sforce.com">
            <n1:username>''' + username + '''</n1:username>
          <n1:password>''' + password + token + '''</n1:password>
        </n1:login>
        </soapenv:Body>
        '''
    login_url = 'https://' + hostname + '/services/Soap/u/' + API_VERSION
    login_response = call_soap_api(login_url, body, 'login')
    session_id_element = login_response.find('.//{urn:partner.soap.sforce.com}sessionId')
    if session_id_element is None:
        exception_message_element = login_response.find('.//{urn:fault.partner.soap.sforce.com}exceptionMessage')
        if exception_message_element is None:
            exception_message = ""
        else:
            exception_message = "\n" + exception_message_element.text
        raise RaccoonError("No session ID found in login response" + exception_message)
    else:
        session_id = session_id_element.text
    metadata_url_element = login_response.find('.//{urn:partner.soap.sforce.com}metadataServerUrl')
    if metadata_url_element is None:
        raise RaccoonError("No metadata endpoint URL found in login response")
    else:
        metadata_url = metadata_url_element.text
    return (session_id, metadata_url)

def get_api_limits(rest_api_url, session_id):
    """Get 24-hour API usage information."""
    try:
        api_limits = call_rest_api(rest_api_url + '/limits', session_id)
    except:
        raise RaccoonError("Failed to get API limit data from REST API - check account permissions")
    try:
        max_requests = int(api_limits['DailyApiRequests']['Max'])
        remaining_requests = int(api_limits['DailyApiRequests']['Remaining'])
    except:
        raise RaccoonError("Failed to extract API limit data from REST API response")
    return (remaining_requests, max_requests)

def validate_objects(rest_api_url, session_id, objects):
    """Use REST API to check validity of supplied objects, guessing where possible, and return a list of qualified API names."""
    validated_objects = []
    sobjects = None
    validation_errors = False
    for obj in objects:
        obj_lower = obj.lower() # Salesforce API is case insensitive for object names but this will help with matching later
        api_name = None
        error_reason = 'not found - check object read permissions otherwise specify using API name'
        # try to catch known gotchas early (without risking false positives)
        if '__mdt' in obj_lower:
            error_reason = 'custom metadata types are not currently supported as they do not fit the same access control model as normal objects'
        elif obj_lower in UNSUPPORTED_OBJECTS:
            error_reason = UNSUPPORTED_OBJECTS[obj_lower]
        else:
            # Assume provided name is the object's API name first then try to match based on label
            try:
                obj_props = call_rest_api(rest_api_url + '/sobjects/' + obj, session_id)
            except requests.HTTPError as e:
                if e.response.status_code != 404:
                    raise e
                else:
                    if sobjects is None:
                        sobjects = call_rest_api(rest_api_url + '/sobjects', session_id)['sobjects'] # 'Describe Global' API call to get full list of objects
                    for sobject in sobjects:
                        # match on label or missing '__c' suffix or missing namespace (strict as otherwise too many matches occur)
                        if sobject['label'].lower() == obj_lower or sobject['labelPlural'].lower() == obj_lower or (sobject['name'].lower() == obj_lower + '__c') or \
                                (sobject['name'].lower().find('__' + obj_lower) > 0 and sobject['name'].lower().find('__' + obj_lower) + len('__' + obj) == len(sobject['name'])):  # supplied name prefixed with '__' matches only if it's the end of object name being tested (without re)
                            if api_name is None:
                                api_name = sobject['name']
                            else:
                                api_name = None
                                error_reason = 'more than one possible match (e.g. '" + api_name + "' vs '" + sobject['name'] + "') - specify using API name'
                                break
            else: # part of try block
                api_name = obj_props['objectDescribe']['name']
        if api_name is not None:
            print("- Found object '" + obj + "' with API name '" + api_name + "'")
            validated_objects.append(api_name)
        else:
            print("! Skipping object '" + obj + "': " + error_reason)
            # prefix name with <space> as a signal for later that the object is invalid (since this character is invalid for API names)
            validated_objects.append(' ' + obj)
            validation_errors = True
    return (validated_objects, validation_errors)

def get_owd_sharing(metadata_url, session_id, obj):
    """ For a given object, return internal and external Organization-wide default sharing settings plus any MasterDetail fields."""
    int_sharing_model = ext_sharing_model = ''
    parent_fields = []
    try:
        # Querying 'CustomObject' to get OWD works for standard objects too
        # Contract OWD settings are tied to Account but for some reason 'externalSharingModel' is never set for Contract - so check Account instead
        if obj.lower() == 'contract':
            obj_props = call_read_metadata(metadata_url, session_id, 'CustomObject', 'Account')
        else:
            obj_props = call_read_metadata(metadata_url, session_id, 'CustomObject', obj)
        int_sharing_model = obj_props.find('.//{http://soap.sforce.com/2006/04/metadata}sharingModel').text
    except Exception:
        print("  - WARNING: could not find defaults for object '" + obj + "' (sharing may not follow typical pattern)")
    else:
        print("  - Internal: ", end="", flush=True)
        if int_sharing_model in SHARING_VALUE_TO_LABEL:
            print(SHARING_VALUE_TO_LABEL[int_sharing_model])
        else:
            print(int_sharing_model + "\n      WARNING: '" + int_sharing_model + "' currently unsupported for object '" + obj + "'")
        # No external sharing model usually means external sharing in general hasn't been enabled
        ext_sharing_model_element = obj_props.find('.//{http://soap.sforce.com/2006/04/metadata}externalSharingModel')
        print("  - External: ", end="", flush=True)
        if ext_sharing_model_element is not None:
            ext_sharing_model = ext_sharing_model_element.text
            if ext_sharing_model in SHARING_VALUE_TO_LABEL:
                print(SHARING_VALUE_TO_LABEL[ext_sharing_model])
            else:
                print(ext_sharing_model + "\n      WARNING: '" + ext_sharing_model + "' currently unsupported for object '" + obj + "'")
        else:
            print("<Undefined>")
        parent_fields = obj_props.findall('.//{http://soap.sforce.com/2006/04/metadata}fields[{http://soap.sforce.com/2006/04/metadata}type="MasterDetail"]')
    return (int_sharing_model, ext_sharing_model, parent_fields)

def revise_sharing_model(sharing_model, read_allows_write):
    """ Revise sharing model, if required, for a child of a MasterDetail relationship based only on the Organisation-wide default for parent."""
    if sharing_model == 'ReadWrite' or (sharing_model == 'Read' and read_allows_write):
        return 'FullAccess'   # although 'transfer' not applicable, ReadWrite isn't enough as delete is conferred in this context, hence FullAccess
    else:
        return sharing_model

def tabulate(perm_sets, table_name, show_headings, max_len_name, max_len_totals):
    """Print details of supplied Permission Sets, split by Profile vs Permission Set and sorted by user type (guest first) then number of active users (largest first).
    
    Arguments:
        table_name -- text to display as heading for first column
        show_headings -- whether or not to display other column headings
        max_len_name -- length of longest Profile/Permission Set name
        max_len_totals -- length of largest combined pair of numbers for active and total users
    """
    if max_len_name < 26:   # length of 'Permission Sets (* Groups)'
        max_len_name = 26
    if len(table_name) > max_len_name:
        max_len_name = len(table_name)
    if max_len_totals + 1 < 12:    # +1 for "/", 12 for length of "Active/Total" as column heading
        max_len_totals = 12
    # print heading
    if show_headings:
        print("  " + table_name + "  " + " "*(max_len_name - len(table_name))
            + " [C]ustom"
            + " Active/Total" + (" "*(max_len_totals-12) if max_len_totals > 12 else "")
            + " [G]uest[E]xt[I]nt")
    else:
        print("  " + table_name)
    # print Profiles
    profiles = [p for p in perm_sets if p['IsOwnedByProfile']]
    if len(profiles) > 0:
        print("  Profiles")
        for p in sorted(profiles, key=itemgetter('hasGuest', 'hasExternal', 'hasInternal', 'active_users'), reverse=True):
            totals_str = str(p['active_users']) + '/' + str(p['total_users'])
            print("  - " + p['Profile']['Name'] + " "*(max_len_name - len(p['Profile']['Name']))
                + (' [C]     ' if p['IsCustom'] else '         ')
                + ' ' + totals_str + " "*(max_len_totals - len(totals_str))
                + (' [G]    ' if p['hasGuest'] else '        ')
                + ('[E]  ' if p['hasExternal'] else '     ')
                + ('[I]' if p['hasInternal'] else '')
                )
    # print Permission Sets
    perm_sets_only = [p for p in perm_sets if not p['IsOwnedByProfile']]
    if len(perm_sets_only) > 0:
        print("  Permission Sets (* Groups)")
        for p in sorted(perm_sets_only, key=itemgetter('hasGuest', 'hasExternal', 'hasInternal', 'active_users'), reverse=True):
            totals_str = str(p['active_users']) + '/' + str(p['total_users'])
            bullet_symbol = '*' if p['Type'] == 'Group' else '-'
            print("  " + bullet_symbol + " " + p['Label'] + " "*(max_len_name - len(p['Label']))
                + (' [C]     ' if p['IsCustom'] else '         ')
                + ' ' + totals_str + " "*(max_len_totals - len(totals_str))
                + (' [G]    ' if p['hasGuest'] else '        ')
                + ('[E]  ' if p['hasExternal'] else '     ')
                + ('[I]' if p['hasInternal'] else '')
                )
    print()

def main():
    """Salesforce object access auditor."""
    banner()
    if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help', '/h', '/?']:
        print("\nUsage is:\n  "+ sys.argv[0] + " <config_file>")
        print("Config file format:\n" + CONFIG_FILE_FORMAT)
        print("Account requires:\n  'API Enabled'\n  'View Setup and Configuration'\n  'Modify Metadata Through Metadata API Functions'\n  Read permission on all specified objects (or 'View All Data')")
        exit(1)
    
    # Try to load config file
    try:
        hostname, username, password, token, objects, check_limits, debug = load_config(sys.argv[1])
    except Exception as e:
        error("Could not load config file - check that format is valid JSON", e, 1)
    
    # Establish REST API endpoint
    try:
        rest_api_url = 'https://' + hostname + '/services/data'
        check_api_ver_supported(rest_api_url)
        rest_api_url += '/v' + API_VERSION
    except Exception as e:
        error("Could not establish REST API endpoint", e, debug)
    
    # Login
    print("\nTarget instance: " + hostname)
    try:
        session_id, metadata_url = login(hostname, username, password, token)
    except Exception as e:
        error("Could not login - check hostname, credentials and account permissions", e, debug)
    print("- Login successful")
    
    # Check API usage
    remaining_requests = None
    max_requests = None
    try:
        remaining_requests, max_requests = get_api_limits(rest_api_url, session_id)
    except Exception as e:
        if check_limits:
            error("Failed to get API usage data and 'checkLimits' set to True", e, debug)
        else:
            print("Failed to get API usage data, but 'checkLimits' set to False so on we go...")
    if remaining_requests is not None and max_requests is not None:
        print("\n" + f"{remaining_requests:,}" + " API requests can be sent to this instance from a 24-hour limit of " + f"{max_requests:,}")
        if check_limits:
            # for each object: validate name, get object properties, get parent object properties (worst case), get parent object permission (worst case), get object permissions, get sharing rules and +1 to call 'Describe Global' (worst case)
            print("- Up to " + str(len(objects) * 6 + 1 + 8) + " further requests are required to complete (" + str(total_reqs) + " requests sent so far)")
            answer = input("- Do you want to continue? Enter 'y' to proceed: ")
            if answer.lower() != 'y':
                error("Permission to continue refused", RaccoonError("API limit checkpoint: user input was '" + answer + "' but 'y' is required or 'checkLimits' set to False"), debug)
    
    # Establish REST query API endpoint
    try:
        rest_query_api_uri = call_rest_api(rest_api_url, session_id)['query']
        rest_query_api_url = 'https://' + hostname + rest_query_api_uri
    except Exception as e:
        error("Could not establish REST query API endpoint", e, debug)
    
    # Validate objects specified by user
    print("\nValidating objects")
    try:
        validated_objects, validation_errors = validate_objects(rest_api_url, session_id, objects)
    except Exception as e:
        error("Could not validate all objects supplied in config file", e, debug)
    if validation_errors:
        answer = input("\n! There were errors validating the objects supplied. Do you want to continue? Enter 'y' to proceed: ")
        if answer.lower() != 'y':
            error("Permission to continue refused", RaccoonError("Object validation checkpoint: user input was '" + answer + "' but 'y' is required"), debug)
    
    # Get permission set information (including profiles)
    try:
        perm_sets = call_rest_query_api(rest_query_api_url, session_id, 'SELECT Id,Label,Type,IsOwnedByProfile,ProfileId,Profile.Name,IsCustom,PermissionsViewAllData,PermissionsModifyAllData FROM PermissionSet')
    except Exception as e:
        error("Could not get Permission Set information - check account permissions", e, debug)
    num_all_perm_sets = len(perm_sets)
    num_profiles = len([p for p in perm_sets if p['IsOwnedByProfile']])
    print("\nEvaluating " + str(num_profiles) + " Profiles and " + str(num_all_perm_sets - num_profiles) + " Permission Sets")
    
    # Check if GROUP BY limitation will be hit in next step (https://developer.salesforce.com/docs/atlas.en-us.soql_sosl.meta/soql_sosl/sforce_api_calls_soql_select_group_by_considerations.htm)
    # This is a perfectly acceptable constraint, especially given the efficiency gain from use of GROUP BY
    try:
        assigned_perm_sets = call_rest_query_api(rest_query_api_url, session_id, 'SELECT COUNT_DISTINCT(PermissionSetId) FROM PermissionSetAssignment')[0]['expr0']
        if assigned_perm_sets > 2000:
            error("Constraint encountered", RaccoonError("More than 2,000 combined Profiles and Permission Sets is not supported"), debug)
    except Exception as e:
        error("Could not check number of assigned Permission Sets", e, debug)
    
    # Remove permission sets with no active users, otherwise add user totals and determine types of user assigned
    perm_set_id = ''
    try:
        # Get number of active users assigned to each Permission Set
        num_active_users_all = call_rest_query_api(rest_query_api_url, session_id, 'SELECT PermissionSetId,COUNT(Id) FROM PermissionSetAssignment WHERE Assignee.IsActive = TRUE GROUP BY PermissionSetId')
        # Get total number of users assigned to each Permission Set
        num_total_users_all = call_rest_query_api(rest_query_api_url, session_id, 'SELECT PermissionSetId,COUNT(Id) FROM PermissionSetAssignment GROUP BY PermissionSetId')
        # Get permission sets assigned to active guest/external/internal users - but see README
        perm_sets_guest = call_rest_query_api(rest_query_api_url, session_id, 'SELECT PermissionSetId FROM PermissionSetAssignment WHERE Assignee.IsActive = TRUE AND Assignee.UserType = \'Guest\' GROUP BY PermissionSetId')
        perm_sets_external = call_rest_query_api(rest_query_api_url, session_id, 'SELECT PermissionSetId FROM PermissionSetAssignment WHERE Assignee.IsActive = TRUE AND Assignee.UserType IN (\'PowerPartner\', \'CspLitePortal\', \'CustomerSuccess\', \'PowerCustomerSuccess\') GROUP BY PermissionSetId')
        perm_sets_internal = call_rest_query_api(rest_query_api_url, session_id, 'SELECT PermissionSetId FROM PermissionSetAssignment WHERE Assignee.IsActive = TRUE AND Assignee.UserType NOT IN (\'Guest\', \'PowerPartner\', \'CspLitePortal\', \'CustomerSuccess\', \'PowerCustomerSuccess\') GROUP BY PermissionSetId')
        # need controlled iteration if simultaneously removing elements from list
        index = 0
        len_list = len(perm_sets)
        while index < len_list:
            perm_set_id = perm_sets[index]['Id']
            # Find number of active users for permission set in num_active_users_all
            # As there should only be one entry at most, could call a for loop that exits but list length relatively small anyway (TODO check how often this is done though)
            perm_set_found = [p for p in num_active_users_all if p['PermissionSetId'] == perm_set_id]
            if len(perm_set_found) == 0:
                perm_sets.pop(index)
                len_list -= 1
            else:
                perm_sets[index]['active_users'] = perm_set_found[0]['expr0']
                perm_sets[index]['total_users'] = [p for p in num_total_users_all if p['PermissionSetId'] == perm_set_id][0]['expr0']
                # Could remove perm_set_found from num_active_users_all and num_total_users_all but list lengths relatively small anyway
                # Determine spread of guest/external/internal users assigned (should be mutually exclusive but just in case...)
                perm_sets[index]['hasGuest'] = False if len([p for p in perm_sets_guest if p['PermissionSetId'] == perm_set_id]) == 0 else True
                perm_sets[index]['hasExternal'] = False if len([p for p in perm_sets_external if p['PermissionSetId'] == perm_set_id]) == 0 else True
                perm_sets[index]['hasInternal'] = False if len([p for p in perm_sets_internal if p['PermissionSetId'] == perm_set_id]) == 0 else True
                index += 1
    except Exception as e:
        error("Could not evaluate Permission Set with Id " + perm_set_id, e, debug)
    num_profiles = len([p for p in perm_sets if p['IsOwnedByProfile']])
    print("- Profiles with active users: " + str(num_profiles))
    print("- Permission Sets with active users: " + str(len(perm_sets) - num_profiles))
    print("- Ignoring " + str(num_all_perm_sets - len(perm_sets)) + " unused Profiles and Permission Sets")
    
    # Get maximum possible lengths for tabulation
    max_len_name = 0
    max_len_totals = 0
    for p in perm_sets:
        l = len(p['Profile']['Name'] if p['IsOwnedByProfile'] else p['Label'])
        if l > max_len_name:
            max_len_name = l
        l = len(str(p['active_users']) + str(p['total_users']))
        if l > max_len_totals:
            max_len_totals = l
    show_headings = True
    
    # Global Sharing Overrides
    print("\nGlobal Sharing Overrides (ALL records for ALL objects)\n" + 54*"-" + "\n")
    modify_all_data = [p for p in perm_sets if p['PermissionsModifyAllData']]
    # cannot imagine there are no instances but what do they say about assumptions...?
    if len(modify_all_data) > 0:
        tabulate(modify_all_data, 'READ/EDIT/DELETE', show_headings, max_len_name, max_len_totals)
        show_headings = False
    # now just read only, avoiding duplicates from ModifyAllData list
    view_all_data = [p for p in perm_sets if p['PermissionsViewAllData'] and not p['PermissionsModifyAllData']]
    if len(view_all_data) > 0:
        tabulate(view_all_data, 'READ', show_headings, max_len_name, max_len_totals)
    if len(modify_all_data) + len(view_all_data) == 0:
        print("- None\n")
    
    # Object Sharing Overrides
    # There's likely some optimisation to be done below but the sharing logic is complex, and the gain is probably relatively small anyway
    print("Object Sharing (ALL records for EACH object)\n" + 44*"-" + "\n")
    for obj in validated_objects:
        # check signal from validate_objects() that object is invalid
        if ' ' in obj:
            print(obj[1:] + ":\n  ! WARNING: object unsupported or invalid (reason given above when 'Validating objects')\n")
            continue
        print(obj + ":")
        print("  Organization-wide default sharing")
        int_sharing_model, ext_sharing_model, parent_fields = get_owd_sharing(metadata_url, session_id, obj)
        # If sharing is 'Controlled By Parent' then work out effective sharing model based on parent and object
        # 'Controlled By Parent' always applies to both internal and external (Salesforce rule), but parent's internal vs external sharing could be different
        parent = ''
        if int_sharing_model == 'ControlledByParent':
            if obj in ('Contact', 'Order', 'Asset'):
                parent = 'Account'
            else:
                if len(parent_fields) == 0:
                    print("    WARNING: sharing model for '" + obj + "' currently unsupported")
                elif len(parent_fields) > 1:
                    print("    WARNING: sharing model for '" + obj + "' currently unsupported as it depends on more than one parent")
                else:
                    reference_to = parent_fields[0].find('.//{http://soap.sforce.com/2006/04/metadata}referenceTo')
                    if reference_to is None:
                        print("    WARNING: sharing model for '" + obj + "' currently unsupported as parent unknown")
                    else:
                        parent = reference_to.text
                    # Check for setting that "allows users with at least Read access to the Master record to create, edit, or delete related Detail records"
                    writeRequiresMasterRead = parent_fields[0].find('.//{http://soap.sforce.com/2006/04/metadata}writeRequiresMasterRead')
                    if writeRequiresMasterRead is None:
                        print("    WARNING: sharing model for '" + obj + "' incomplete as 'writeRequiresMasterRead' field not found")
                    else:
                        # make the variable name clearer!
                        read_allows_write = writeRequiresMasterRead.text.lower() == 'true'
            if parent:
                print("  Parent object: '" + parent + "'")
                # It's possible we got the OWD sharing previously but storing that and checking is more trouble than refetching
                # Parent fields not needed as hierarchical parenting not supported, so preserve parent_fields variable
                int_sharing_model, ext_sharing_model, dev_null = get_owd_sharing(metadata_url, session_id, parent)
                if int_sharing_model == 'ControlledByParent':
                    print("    WARNING: sharing model for '" + obj + "' currently unsupported as parent is more than one level above child")
                # Effective sharing model can be more privileged under certain circumstances
                if len(parent_fields) > 0:     # MasterDetail relationship
                    # Only OWD sharing model considered: effect on PermissionsViewAllRecords and PermissionsModifyAllRecords considered later
                    int_sharing_model = revise_sharing_model(int_sharing_model, read_allows_write)
                    ext_sharing_model = revise_sharing_model(ext_sharing_model, read_allows_write)
        print()
        
        # Get object permissions and object-level sharing overrides, factoring in parent as required
        try:
            obj_perms = call_rest_query_api(rest_query_api_url, session_id, 'SELECT ParentId,PermissionsRead,PermissionsEdit,PermissionsDelete,PermissionsViewAllRecords,PermissionsModifyAllRecords FROM ObjectPermissions WHERE SObjectType = \'' + obj + '\'')
        except Exception as e:
            error("Could not get permissions for object '" + obj + "'", e, debug)
        # Add keys to cover possibility PermissionsViewAllRecords / PermissionsModifyAllRecords comes from parent
        for p in obj_perms:
            p['PermissionsViewAllRecordsFromParent'] = p['PermissionsModifyAllRecordsFromParent'] = False
        if len(obj_perms) == 0:
            print("  WARNING: no Profiles or Permission Sets configured with specific access to '" + obj + "' (access may not follow typical pattern)\n")
            continue
        if parent and (obj not in ('Contact', 'Order')):
            # We need to consider PermissionsViewAllRecords and PermissionsModifyAllRecords from parent object too as these give effective equivalent access to child
            try:
                parent_obj_perms = call_rest_query_api(rest_query_api_url, session_id, 'SELECT ParentId,PermissionsViewAllRecords,PermissionsModifyAllRecords FROM ObjectPermissions WHERE SObjectType = \'' + parent + '\'')
                if len(parent_obj_perms) == 0:
                    print("  WARNING: no Profiles or Permission Sets configured with specific access to '" + parent + "' (access may not follow typical pattern)\n")
                else:
                    # Where PermissionsViewAllRecords / PermissionsModifyAllRecords is False for child, check parent, but object permission not guaranteed so note separately
                    # PermissionsModifyAllRecords implies PermissionsViewAllRecords but to optimise on this would require filtering so swings and roundabouts
                    for perm_all_records in ('PermissionsViewAllRecords', 'PermissionsModifyAllRecords'):
                        # get IDs of permission sets without perm_all_records permission on child
                        perm_all_records_false_ids = [p['ParentId'] for p in obj_perms if not p[perm_all_records]]
                        # get IDs of permission sets where with perm_all_records permission on parent
                        perm_all_records_parent_ids = [p['ParentId'] for p in parent_obj_perms if p[perm_all_records]]
                        # cross-check
                        for p in perm_all_records_false_ids:
                            if p in perm_all_records_parent_ids:
                                # note as PermissionsViewAllRecordsFromParent / PermissionsModifyAllRecordsFromParent
                                [q for q in obj_perms if q['ParentId'] == p][0][perm_all_records + 'FromParent'] = True
            except Exception as e:
                error("Could not establish permissions for parent object '" + parent + "' for object '" + obj + "'", e, debug)
        
        # Display only permission sets with active users, listing with their maximum privileges
        # Start by removing ModifyAllData entries as these have been shown, but keep ViewAllData for now in case edit/delete has been added at object level
        # Need to keep perm_sets intact for next object
        perm_sets_filtered = [p for p in perm_sets if not p['PermissionsModifyAllData']]
        # Could filter obj_perms too but probably little to gain
        # Continue in descending order of privilege to avoid duplication...
        
        # enumerate all ways read/edit/delete ('red') could be granted
        # get IDs of permission sets with PermissionsModifyAllRecords
        modify_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsModifyAllRecords']]
        # get permission sets with those IDs
        perm_sets_red = [p for p in perm_sets_filtered if p['Id'] in modify_all_ids]
        if len(perm_sets_red) > 0:
            # filter out these permission sets from further consideration
            perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in modify_all_ids]
        # ext_sharing_model cannot be more relaxed than int_sharing_model so external can only be FullAccess if internal is too
        obj_red_ids = [p['ParentId'] for p in obj_perms if p['PermissionsDelete']]
        if int_sharing_model == 'FullAccess':
            # get IDs of permission sets with PermissionsDelete on the object (implies read/edit)
            if ext_sharing_model == 'FullAccess':
                # get permission sets with those IDs for any user type assigned
                perm_sets_obj_red = [p for p in perm_sets_filtered if p['Id'] in obj_red_ids]
            else:
                # get permission sets with those IDs only if internal users assigned
                perm_sets_obj_red = [p for p in perm_sets_filtered if p['Id'] in obj_red_ids and p['hasInternal']]
            if len(perm_sets_obj_red) > 0:
                perm_sets_red.extend(perm_sets_obj_red)
                # filter out these permission sets from further consideration
                ids = [p['Id'] for p in perm_sets_obj_red]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        # consider PermissionsModifyAllRecords from parent (object permissions not implicit)
        if parent and (obj not in ('Contact', 'Order')):
            # get IDs of permission sets with PermissionsModifyAllRecordsFromParent
            modify_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsModifyAllRecordsFromParent']]
            # get permission sets with those IDs
            p_sets = [p for p in perm_sets_filtered if p['Id'] in modify_all_ids]
            # filter those permission sets further to check for 'red' object permissions
            perm_sets_obj_red = [p for p in p_sets if p['Id'] in obj_red_ids]
            if len(perm_sets_obj_red) > 0:
                perm_sets_red.extend(perm_sets_obj_red)
                # filter out these permission sets from further consideration
                ids = [p['Id'] for p in perm_sets_obj_red]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        # consider Master-Detail relationships where read allows write (which includes delete in this context)
        if parent and len(parent_fields) > 0 and read_allows_write:
            # get IDs of permission sets with PermissionsViewAllRecords (covers ViewAllData too)
            view_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsViewAllRecordsFromParent']]
            # get permission sets with those IDs
            p_sets = [p for p in perm_sets_filtered if p['Id'] in view_all_ids]
            # filter those permission sets further to check for 'red' object permissions
            perm_sets_obj_red = [p for p in p_sets if p['Id'] in obj_red_ids]
            if len(perm_sets_obj_red) > 0:
                perm_sets_red.extend(perm_sets_obj_red)
                # filter out these permission sets from further consideration
                ids = [p['Id'] for p in perm_sets_obj_red]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        
        # enumerate all ways read/edit ('re') could be granted (no comments as similar logic)
        perm_sets_re = []
        obj_re_ids = [p['ParentId'] for p in obj_perms if p['PermissionsEdit']]   # implies read
        if int_sharing_model in ('FullAccess', 'ReadWriteTransfer', 'ReadWrite'):
            if ext_sharing_model in ('FullAccess', 'ReadWriteTransfer', 'ReadWrite'):
                perm_sets_re = [p for p in perm_sets_filtered if p['Id'] in obj_re_ids]
            else:
                perm_sets_re = [p for p in perm_sets_filtered if p['Id'] in obj_re_ids and p['hasInternal']]
            if len(perm_sets_re) > 0:
                ids = [p['Id'] for p in perm_sets_re]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        # consider PermissionsModifyAllRecords from parent (object permissions not implicit)
        if parent and (obj not in ('Contact', 'Order')):
            modify_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsModifyAllRecordsFromParent']]
            p_sets = [p for p in perm_sets_filtered if p['Id'] in modify_all_ids]
            perm_sets_obj_re = [p for p in p_sets if p['Id'] in obj_re_ids]
            if len(perm_sets_obj_re) > 0:
                perm_sets_re.extend(perm_sets_obj_re)
                ids = [p['Id'] for p in perm_sets_obj_re]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        # consider Master-Detail relationships where read allows write
        if parent and len(parent_fields) > 0 and read_allows_write:
            # get IDs of permission sets with PermissionsViewAllRecords (covers ViewAllData too)
            view_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsViewAllRecordsFromParent']]
            # get permission sets with those IDs
            p_sets = [p for p in perm_sets_filtered if p['Id'] in view_all_ids]
            # filter those permission sets further to check for 'red' object permissions
            perm_sets_obj_re = [p for p in p_sets if p['Id'] in obj_re_ids]
            if len(perm_sets_obj_re) > 0:
                perm_sets_re.extend(perm_sets_obj_re)
                # filter out these permission sets from further consideration
                ids = [p['Id'] for p in perm_sets_obj_re]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        
        # enumerate all ways read ('r') could be granted (no comments as similar logic)
        # now remove ViewAllData entries
        perm_sets_filtered = [p for p in perm_sets_filtered if not p['PermissionsViewAllData']]
        view_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsViewAllRecords']]
        perm_sets_r = [p for p in perm_sets_filtered if p['Id'] in view_all_ids]
        if len(perm_sets_r) > 0:
            perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in view_all_ids]
        obj_r_ids = [p['ParentId'] for p in obj_perms if p['PermissionsRead']]
        if int_sharing_model in ('FullAccess', 'ReadWriteTransfer', 'ReadWrite', 'Read'):
            if ext_sharing_model in ('FullAccess', 'ReadWriteTransfer', 'ReadWrite', 'Read'):
                perm_sets_obj_r = [p for p in perm_sets_filtered if p['Id'] in obj_r_ids]
            else:
                perm_sets_obj_r = [p for p in perm_sets_filtered if p['Id'] in obj_r_ids and p['hasInternal']]
            if len(perm_sets_obj_r) > 0:
                perm_sets_r.extend(perm_sets_obj_r)
                ids = [p['Id'] for p in perm_sets_obj_r]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
        # consider PermissionsViewAllRecords / PermissionsModifyAllRecords from parent (object permissions not implicit)
        if parent and (obj not in ('Contact', 'Order')):
            modify_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsModifyAllRecordsFromParent']]
            p_sets = [p for p in perm_sets_filtered if p['Id'] in modify_all_ids]
            perm_sets_obj_r = [p for p in p_sets if p['Id'] in obj_r_ids]
            if len(perm_sets_obj_r) > 0:
                perm_sets_r.extend(perm_sets_obj_r)
                ids = [p['Id'] for p in perm_sets_obj_r]
                perm_sets_filtered = [p for p in perm_sets_filtered if p['Id'] not in ids]
            view_all_ids = [p['ParentId'] for p in obj_perms if p['PermissionsViewAllRecordsFromParent']]
            p_sets = [p for p in perm_sets_filtered if p['Id'] in view_all_ids]
            perm_sets_obj_r = [p for p in p_sets if p['Id'] in obj_r_ids]
            # no need to filter out these as we're done
            perm_sets_r.extend(perm_sets_obj_r)
        
        show_headings = True
        if len(perm_sets_red) > 0:
            tabulate(perm_sets_red, 'READ/EDIT/DELETE', show_headings, max_len_name, max_len_totals)
            show_headings = False
        if len(perm_sets_re) > 0:
            tabulate(perm_sets_re, 'READ/EDIT', show_headings, max_len_name, max_len_totals)
            show_headings = False
        if len(perm_sets_r) > 0:
            tabulate(perm_sets_r, 'READ', show_headings, max_len_name, max_len_totals)
        
        # check for Sharing Rules - difficult to parse, just warn if in place
        try:
            sharing_rules = call_read_metadata(metadata_url, session_id, 'SharingRules', obj)
        except Exception as e:
            error("Could not query Sharing Rules - check account permissions", e, debug)
        sharing_guest_rules = sharing_rules.find('.//{http://soap.sforce.com/2006/04/metadata}sharingGuestRules')
        sharing_criteria_rules = sharing_rules.find('.//{http://soap.sforce.com/2006/04/metadata}sharingCriteriaRules')
        sharing_owner_rules = sharing_rules.find('.//{http://soap.sforce.com/2006/04/metadata}sharingOwnerRules')
        sharing_territory_rules = sharing_rules.find('.//{http://soap.sforce.com/2006/04/metadata}sharingTerritoryRules')
        if sharing_guest_rules is not None or sharing_criteria_rules is not None or sharing_owner_rules is not None or sharing_territory_rules is not None:
            print("  Sharing Rules (manual check required):")
            if sharing_guest_rules is not None:
                print("  - Guest user rules configured (extending access to unuathenticated users)")
            if sharing_criteria_rules is not None:
                print("  - Criteria-based rules configured")
            if sharing_owner_rules is not None:
                print("  - Ownership-based rules configured")
            if sharing_territory_rules is not None:
                print("  - Territory-based rules configured")
        if sharing_guest_rules is not None or sharing_criteria_rules is not None or sharing_owner_rules is not None or sharing_territory_rules is not None:
            print()
    
    print("Total API requests sent: " + str(total_reqs))

############
### Main ###

if __name__ == "__main__":
    main()
