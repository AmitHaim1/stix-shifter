import json
import unittest
from stix_shifter_utils.stix_translation.src.json_to_stix import json_to_stix_translator
from stix_shifter_modules.cbcloud.entry_point import EntryPoint
from stix_shifter_utils.stix_translation.src.utils.transformer_utils import get_module_transformers

MODULE = "cbcloud"
entry_point = EntryPoint()
map_data = entry_point.get_results_translator().map_data
data_source = {
    "type": "identity",
    "id": "identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d1",
    "name": "cbcloud",
    "identity_class": "events"
}
options = {}

DATA = {
  "type": "endpoint.event.procstart",
  "process_guid": "ABCD1234-006e8d46-00001310-00000000-1d5fd46cc37d700",
  "parent_guid": "ABCD1234-006e8d46-00000290-00000000-1d5fa5dbbaa12ce",
  "backend_timestamp": "2020-03-25 22:38:54 +0000 UTC",
  "org_key": "ABCD1234",
  "device_id": "7245126",
  "device_name": "cbc-win10",
  "device_external_ip": "72.152.92.146",
  "device_os": "WINDOWS",
  "device_group": "Windows Group",
  "action": "ACTION_CREATE_PROCESS",
  "schema": 1,
  "event_description": "The application \"<share><link hash=\"0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" invoked the application \"<share><link hash=\"0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\". ",
  "alert_id": "WXYZ0987",
  "event_id": "54885ebc6ee911eabc70416f8358e4f2",
  "device_timestamp": "2020-03-25 22:38:03.353 +0000 UTC",
  "process_reputation": "REP_RESOLVING",
  "parent_repuation": "",
  "process_pid": 4880,
  "parent_pid": 656,
  "process_path": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
  "parent_path": "c:\\windows\\system32\\services.exe",
  "process_hash": [
    "3623a0e7cdcf3310ffb4c87c5b43ae02",
    "0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043"
  ],
  "parent_hash": [
    "db896369fb58241adf28515e3765c514",
    "a2e369df26c88015fe1f97c7542d6023b5b1e4830c25f94819507ee5bcb1dfcc"
  ],
  "process_cmdline": "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --flag-switches-begin --flag-switches-end --enable-audio-service-sandbox",
  "parent_cmdline": "",
  "process_username": "CBC-WIN10\\user",
  "sensor_action": "ALLOW",
  "childproc_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
  "childproc_hash": [
    "3623a0e7cdcf3310ffb4c87c5b43ae02",
    "0f407d7194e7955e312b177b16cc409ac89b4d0494c60ce75469fd4c474d4043"
  ],
  "target_cmdline": "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility --field-trial-handle=1656,13710686576560040528,13403776044656688818,131072 --lang=en-US --service-sandbox-type=utility --enable-audio-service-sandbox --mojo-platform-channel-handle=5236 --ignored=\" --type=renderer \" /prefetch:8"
}

class TestCBCloudResultsToStix(unittest.TestCase):
    @staticmethod
    def get_first(itr, constraint):
        """
        return the obj in the itr if constraint is true
        """
        return next(
            (obj for obj in itr if constraint(obj)),
            None
        )

    @staticmethod
    def get_first_of_type(itr, typ):
        """
        to check whether the object belongs to respective stix object
        """
        return TestCBCloudResultsToStix.get_first(itr, lambda o: isinstance(o, dict) and o.get('type') == typ)
    
    @staticmethod
    def test_common_prop():
        """
        to test the common stix object properties
        """

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [DATA], get_module_transformers(MODULE), options)
        
        assert result_bundle['type'] == 'bundle'
        result_bundle_objects = result_bundle['objects']

        result_bundle_identity = result_bundle_objects[0]
        assert result_bundle_identity['type'] == data_source['type']
        assert result_bundle_identity['id'] == data_source['id']
        assert result_bundle_identity['name'] == data_source['name']
        assert result_bundle_identity['identity_class'] == data_source['identity_class']

        observed_data = result_bundle_objects[1]
        assert observed_data['id'] is not None
        assert observed_data['type'] == "observed-data"
        assert observed_data['created_by_ref'] == result_bundle_identity['id']
        assert observed_data['modified'] is not None
        assert observed_data['created'] is not None
        assert observed_data['first_observed'] is not None
        assert observed_data['last_observed'] is not None
        assert observed_data['number_observed'] is not None
        # assert False
    
    def test_file_process_json_to_stix(self):
        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [DATA], get_module_transformers(MODULE), options)

        result_bundle_objects = result_bundle['objects']

        result_bundle_identity = result_bundle_objects[0]
        assert result_bundle_identity['type'] == data_source['type']

        observed_data = result_bundle_objects[1]

        assert 'objects' in observed_data
        objects = observed_data['objects']

        file_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'file')
        file_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'file')
        #############################################################################################

        process_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'process')
        child_index = process_obj['child_refs']
        child_obj = objects[child_index]
        assert child_obj is not None, 'child_refs object type not found'
        assert child_obj.keys() == {'type', 'command_line ', 'binary_ref', 'pid'}

        binary_ref_index = child_obj['binary_ref']
        binary_ref_obj = objects[binary_ref_index]
        assert binary_ref_obj is not None, 'binary_ref object type not found'
        assert binary_ref_obj.keys() == {'type', 'hashes', 'name'}
        assert  binary_ref_obj['name'] == "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe"
        assert  binary_ref_obj['hashes']['SHA-256'] == "af96a5c7c77082e33b2a10555a46f56bdff12344f8a289d6a7a3118d17a63d95"

        finding_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'x-ibm-finding')

        assert finding_obj is not None, 'finding object type not found'
        assert finding_obj .keys() == {'type', 'severity', 'finding_type'}
        assert finding_obj['type'] == 'x-ibm-finding'
        assert finding_obj['severity'] == 2
        assert finding_obj['finding_type'] == 'WARNING'

        event_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'x_oca_event')
        assert event_obj is not None, 'event object type not found'
        assert event_obj.keys() == {'type', 'category', 'code'}
        assert event_obj['type'] == 'x_oca_event'
        assert event_obj['code'] == "54885ebc6ee911eabc70416f8358e4f2"
        assert event_obj['category'] == "childproc"

        ###############################################################################################
        assert file_obj is not None, 'file object type not found'
        assert file_obj .keys() == {'type', 'name'}
        assert file_obj['type'] == 'file'
        assert file_obj['name'] == 'c:\\windows\\system32\\svchost.exe'

        parent_ref_index = process_obj['parent_ref']
        parent_ref_obj = objects[parent_ref_index]
        assert process_obj is not None, 'parent_ref object type not found'
        assert parent_ref_obj.keys() == {'type', 'x_unique_id', 'binary_ref', 'pid'}
        assert parent_ref_obj['type'] == 'process'
        assert parent_ref_obj['x_unique_id'] == 'X79DF22N-0000368c-0000022c-00000000-1d6dcd71a37dfe5'
        assert parent_ref_obj['pid'] == 556

        parent_binary_ref_index = parent_ref_obj['binary_ref']
        parent_binary_ref_obj = objects[parent_binary_ref_index]
        assert parent_binary_ref_obj is not None, 'parent_binary_ref object type not found'
        assert parent_binary_ref_obj.keys() == {'type', 'hashes'}
        assert parent_binary_ref_obj['type'] == 'file'
        assert parent_binary_ref_obj['hashes']['MD5'] == 'e0c7813a97ca7947ff5c18a8f3b61a45'

        host_obj = TestCBCloudResultsToStix.get_first_of_type(objects.values(), 'x-oca-host')
        assert host_obj is not None, 'host object type not found'
        assert host_obj.keys() == {'type', 'ip_refs', 'hostname'}
        assert host_obj['type'] == 'x-oca-host'
        assert host_obj['hostname'] == 'iestestmachine1'

        host_ip_refs_index = host_obj['ip_refs']
        host_ip_refs_obj = objects[host_ip_refs_index]
        assert host_ip_refs_obj is not None, 'host_ip_refs object type not found'
        assert host_ip_refs_obj.keys() == {'type', 'value'}
        assert host_ip_refs_obj['value'] == "46.135.79.144"

