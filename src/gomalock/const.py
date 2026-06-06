"""Defines constants and enumerations for Sesame communication.

This module provides the necessary enumerations, status flags, opcodes, and
other constants required to interact with Sesame BLE devices.
"""

from enum import Enum, IntFlag, auto


class KeyLevel(Enum):
    """Represents the authorization levels for Sesame keys."""

    OWNER = 0
    MANAGER = 1


class ProductModel(Enum):
    """Enumerates the supported Sesame device models and their identifiers."""

    SESAME5 = 5
    SESAME5_PRO = 7
    SESAME_TOUCH_PRO = 9
    SESAME_TOUCH = 10
    SESAME5_USA = 16


class ModelGroup(Enum):
    """Groups product models for device compatibility checks."""

    SESAME5 = {
        ProductModel.SESAME5,
        ProductModel.SESAME5_PRO,
        ProductModel.SESAME5_USA,
    }
    SESAME_TOUCH = {ProductModel.SESAME_TOUCH, ProductModel.SESAME_TOUCH_PRO}


class PacketType(IntFlag):
    """Flags for the 1-byte header in BLE communication packets."""

    BEGINNING = 0b001
    PLAINTEXT_END = 0b010
    ENCRYPTED_END = 0b100


class MechStatusBitFlag(IntFlag):
    """Flags indicating mechanical state, direction, and battery status."""

    IS_CLUTCH_FAILED = 0b00000001
    IS_IN_LOCK_RANGE = 0b00000010
    IS_IN_UNLOCK_RANGE = 0b00000100
    IS_CRITICAL = 0b00001000
    IS_STOP = 0b00010000
    IS_BATTERY_CRITICAL = 0b00100000
    IS_CLOCKWISE = 0b01000000


class DeviceStatus(Enum):
    """Represents the connection and authentication state of the device."""

    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    LOGGING_IN = auto()
    LOGGED_IN = auto()
    DISCONNECTING = auto()


class ItemCode(Enum):
    """Codes representing specific commands, settings, or data types."""

    NONE = 0
    REGISTRATION = 1
    LOGIN = 2
    USER = 3
    HISTORY = 4
    VERSION_TAG = 5
    DISCONNECT_REBOOT_NOW = 6
    ENABLE_DFU = 7
    TIME = 8
    BLE_CONNECTION_PARAM = 9
    BLE_ADV_PARAM = 10
    AUTOLOCK = 11
    SERVER_ADV_KICK = 12
    SSMTOKEN = 13
    INITIAL = 14
    IRER = 15
    TIME_PHONE = 16
    MAGNET = 17
    SSM2_ITEM_CODE_HISTORY_DELETE = 18
    SENSOR_INVERVAL = 19
    SENSOR_INVERVAL_GET = 20

    MECH_SETTING = 80
    MECH_STATUS = 81
    LOCK = 82
    UNLOCK = 83
    MOVE_TO = 84
    DRIVE_DIRECTION = 85
    STOP = 86
    DETECT_DIR = 87
    TOGGLE = 88
    CLICK = 89
    DOOR_OPEN = 90
    DOOR_CLOSE = 91
    OPS_CONTROL = 92

    SCRIPT_SETTING = 93
    SCRIPT_SELECT = 94
    SCRIPT_CURRENT = 95
    SCRIPT_NAME_LIST = 96
    ADD_SESAME = 101
    PUB_KEY_SESAME = 102
    REMOVE_SESAME = 103
    RESET = 104
    NOTIFY_LOCK_DOWN = 106

    SSM_OS3_CARD_CHANGE = 107
    SSM_OS3_CARD_DELETE = 108
    SSM_OS3_CARD_GET = 109
    SSM_OS3_CARD_NOTIFY = 110
    SSM_OS3_CARD_LAST = 111
    SSM_OS3_CARD_FIRST = 112
    SSM_OS3_CARD_MODE_GET = 113
    SSM_OS3_CARD_MODE_SET = 114

    SSM_OS3_FINGERPRINT_CHANGE = 115
    SSM_OS3_FINGERPRINT_DELETE = 116
    SSM_OS3_FINGERPRINT_GET = 117
    SSM_OS3_FINGERPRINT_NOTIFY = 118
    SSM_OS3_FINGERPRINT_LAST = 119
    SSM_OS3_FINGERPRINT_FIRST = 120
    SSM_OS3_FINGERPRINT_MODE_GET = 121
    SSM_OS3_FINGERPRINT_MODE_SET = 122

    SSM_OS3_PASSCODE_CHANGE = 123
    SSM_OS3_PASSCODE_DELETE = 124
    SSM_OS3_PASSCODE_GET = 125
    SSM_OS3_PASSCODE_NOTIFY = 126
    SSM_OS3_PASSCODE_LAST = 127
    SSM_OS3_PASSCODE_FIRST = 128
    SSM_OS3_PASSCODE_MODE_GET = 129
    SSM_OS3_PASSCODE_MODE_SET = 130

    HUB3_ITEM_CODE_WIFI_SSID = 131
    HUB3_ITEM_CODE_SSID_FIRST = 132
    HUB3_ITEM_CODE_SSID_NOTIFY = 133
    HUB3_ITEM_CODE_SSID_LAST = 134
    HUB3_ITEM_CODE_WIFI_PASSWORD = 135
    HUB3_UPDATE_WIFI_SSID = 136
    HUB3_MATTER_PAIRING_CODE = 137

    SSM_OS3_PASSCODE_ADD = 138
    SSM_OS3_CARD_CHANGE_VALUE = 139
    SSM_OS3_CARD_ADD = 140
    SSM_OS3_CARD_MOVE = 141
    SSM_OS3_PASSCODE_MOVE = 142

    SSM_OS3_IR_MODE_SET = 143
    SSM_OS3_IR_CODE_CHANGE = 144
    SSM_OS3_IR_CODE_EMIT = 145
    SSM_OS3_IR_CODE_GET = 146
    SSM_OS3_IR_CODE_LAST = 147
    SSM_OS3_IR_CODE_FIRST = 148
    SSM_OS3_IR_CODE_DELETE = 149
    SSM_OS3_IR_MODE_GET = 150
    SSM_OS3_IR_CODE_NOTIFY = 151

    HUB3_MATTER_PAIRING_WINDOW = 153

    SSM_OS3_FACE_CHANGE = 154
    SSM_OS3_FACE_DELETE = 155
    SSM_OS3_FACE_GET = 156
    SSM_OS3_FACE_NOTIFY = 157
    SSM_OS3_FACE_LAST = 158
    SSM_OS3_FACE_FIRST = 159
    SSM_OS3_FACE_MODE_GET = 160
    SSM_OS3_FACE_MODE_SET = 161

    SSM_OS3_PALM_CHANGE = 162
    SSM_OS3_PALM_DELETE = 163
    SSM_OS3_PALM_GET = 164
    SSM_OS3_PALM_NOTIFY = 165
    SSM_OS3_PALM_LAST = 166
    SSM_OS3_PALM_FIRST = 167
    SSM_OS3_PALM_MODE_GET = 168
    SSM_OS3_PALM_MODE_SET = 169

    BOT2_ITEM_CODE_RUN_SCRIPT_0 = 170
    BOT2_ITEM_CODE_RUN_SCRIPT_1 = 171
    BOT2_ITEM_CODE_RUN_SCRIPT_2 = 172
    BOT2_ITEM_CODE_RUN_SCRIPT_3 = 173
    BOT2_ITEM_CODE_RUN_SCRIPT_4 = 174
    BOT2_ITEM_CODE_RUN_SCRIPT_5 = 175
    BOT2_ITEM_CODE_RUN_SCRIPT_6 = 176
    BOT2_ITEM_CODE_RUN_SCRIPT_7 = 177
    BOT2_ITEM_CODE_RUN_SCRIPT_8 = 178
    BOT2_ITEM_CODE_RUN_SCRIPT_9 = 179

    ADD_HUB3 = 180
    BOT2_ITEM_CODE_EDIT_SCRIPT = 181
    STP_ITEM_CODE_CARDS_ADD = 182
    STP_ITEM_CODE_DEVICE_STATUS = 183

    REMOTE_NANO_ITEM_CODE_SET_TRIGGER_DELAYTIME = 190
    REMOTE_NANO_ITEM_CODE_PUB_TRIGGER_DELAYTIME = 191
    SSM_OS3_FACE_MODE_DELETE_NOTIFY = 192
    SSM_OS3_PALM_MODE_DELETE_NOTIFY = 193

    SSM_OS3_RADAR_PARAM_SET = 200
    SSM_OS3_RADAR_PARAM_PUBLISH = 201

    SSM3_ITEM_CODE_BATTERY_VOLTAGE = 202
    SSM3_ITEM_CODE_SESAME_UNSUPPORT = 204
    SS3_ITEM_CODE_SET_ADV_PRODUCT_TYPE = 205
    SSM3_ITEM_CODE_BLE_TX_POWER_SETTING = 206
    HUB3_ITEM_CODE_RELAY_SWITCH = 208
    HUB3_ITEM_CODE_NETWORK_TYPE = 209


class OpCode(Enum):
    """Operation codes indicating the type of message being transmitted."""

    CREATE = 0x01
    READ = 0x02
    UPDATE = 0x03
    DELETE = 0x04
    SYNC = 0x05
    ASYNC = 0x06
    RESPONSE = 0x07
    PUBLISH = 0x08
    UNDEFINE = 0x10


class ResultCode(Enum):
    """Codes indicating the success or specific failure reason of a command."""

    SUCCESS = 0
    INVALID_FORMAT = 1
    NOT_SUPPORTED = 2
    STORAGE_FAIL = 3
    INVALID_SIG = 4
    NOT_FOUND = 5
    UNKNOWN = 6
    BUSY = 7
    INVALID_PARAM = 8
    INVALID_ACTION = 9


VOLTAGE_LEVELS = (
    5.85,
    5.82,
    5.79,
    5.76,
    5.73,
    5.70,
    5.65,
    5.60,
    5.55,
    5.50,
    5.40,
    5.20,
    5.10,
    5.0,
    4.8,
    4.6,
)
"""Predefined battery voltage levels used to calculate remaining percentage."""

BATTERY_PERCENTAGES = (
    100.0,
    95.0,
    90.0,
    85.0,
    80.0,
    70.0,
    60.0,
    50.0,
    40.0,
    32.0,
    21.0,
    13.0,
    10.0,
    7.0,
    3.0,
    0.0,
)
"""Battery percentages that map to the corresponding values in VOLTAGE_LEVELS."""

COMPANY_ID = 0x055A
"""The assigned Bluetooth SIG company identifier for CANDYHOUSE, Inc."""
UUID_SERVICE = "0000fd81-0000-1000-8000-00805f9b34fb"
"""The primary GATT service UUID for Sesame BLE communication."""
UUID_WRITE = "16860002-a5ae-9856-b6d3-dbb4c676993e"
"""The GATT characteristic UUID for sending commands to the device."""
UUID_NOTIFICATION = "16860003-a5ae-9856-b6d3-dbb4c676993e"
"""The GATT characteristic UUID for receiving data from the device."""
HISTORY_TAG_MAX_LEN = 20
"""The maximum allowed byte length for a history tag."""
MTU_SIZE = 20
"""The maximum transmission unit size used for chunking BLE packets."""

SCAN_TIMEOUT = 30
"""The default duration in seconds to wait when scanning for devices."""
PUBLISH_TIMEOUT = 5
"""The maximum time in seconds to wait for an expected publish message."""
RESPONSE_TIMEOUT = 2
"""The maximum time in seconds to wait for a command response."""
RECONNECT_MAX_BACKOFF = 32
"""The maximum delay in seconds between auto-reconnection attempts."""
