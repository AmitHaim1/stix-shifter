from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer
from stix_shifter_utils.utils import logger
import base64

LOGGER = logger.set_logger(__name__)


class ExtractSHA256ValueFromArray(ValueTransformer):
    """A value transformer to convert QRadar ObjectName to windows-registry-key.key STIX"""

    @staticmethod
    def transform(registry):

        try:
            val1 = registry[0]
            val2 = None
            if len(registry) > 1:
                val2 = registry[1]
            return val1 if len(val1) == 64 else val2
        except ValueError:
            LOGGER.error("Cannot convert root key to Stix formatted windows registry key")


class ExtractMD5ValueFromArray(ValueTransformer):
    @staticmethod
    def transform(registry):

        try:
            val1 = registry[0]
            val2 = None
            if len(registry) > 1:
                val2 = registry[1]
            return val1 if len(val1) == 32 else val2
        except ValueError:
            LOGGER.error("Cannot convert root key to Stix formatted windows registry key")


class ToBase64(ValueTransformer):
    """A value transformer for expected base 64 values"""

    @staticmethod
    def transform(obj):
        try:
            return base64.b64encode(obj.encode()).decode('ascii')
        except ValueError:
            LOGGER.error("Cannot convert input to base64")






