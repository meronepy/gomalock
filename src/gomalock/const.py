"""Constants and enumerations for Sesame BLE communication.

This module defines various constants and enumerations used throughout the
`gomalock` library for interacting with Sesame devices.
"""

from enum import Enum, IntFlag, auto

COMPANY_ID = 0x055A
"""The company ID for CANDYHOUSE, Inc."""
UUID_SERVICE = "0000fd81-0000-1000-8000-00805f9b34fb"
"""The UUID for the primary Sesame BLE service."""
UUID_WRITE = "16860002-a5ae-9856-b6d3-dbb4c676993e"
"""The UUID for the GATT characteristic used to write commands."""
UUID_NOTIFICATION = "16860003-a5ae-9856-b6d3-dbb4c676993e"
"""The UUID for the GATT characteristic used to receive notifications."""

HISTORY_TAG_MAX_LEN = 20
"""Max history tag length."""
MTU_SIZE = 20
"""The MTU for BLE communication."""
SCAN_TIMEOUT = 10
"""Timeout for BLE scanning to get advertisement data."""
SESSION_TOKEN_TIMEOUT = 5
"""Timeout for waiting for a session token."""
RESPONSE_TIMEOUT = 2
"""Timeout for waiting for a response from the device."""

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
"""Voltage levels for battery percentage calculation."""
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
"""Battery percentage corresponding to the voltage levels."""


class ProductModels(Enum):
    """The model IDs received in the advertisement data."""

    SESAME5 = 5
    SESAME5_PRO = 7
    SESAME_TOUCH_PRO = 9
    SESAME_TOUCH = 10
    SESAME5_USA = 16


class PacketTypes(IntFlag):
    """Packet type flags used in the 1-byte header of BLE packets."""

    BEGINNING = 0b001
    PLAINTEXT_END = 0b010
    ENCRYPTED_END = 0b100


class MechStatusBitFlags(IntFlag):
    """Mechanical status flags for Sesame devices."""

    IS_CLUTCH_FAILED = 0b00000001
    IS_IN_LOCK_RANGE = 0b00000010
    IS_IN_UNLOCK_RANGE = 0b00000100
    IS_CRITICAL = 0b00001000
    IS_STOP = 0b00010000
    IS_BATTERY_CRITICAL = 0b00100000
    IS_CLOCKWISE = 0b01000000


class DeviceStatus(Enum):
    """Device status of Sesame."""

    NO_BLE_SIGNAL = auto()
    BLE_CONNECTING = auto()
    BLE_LOGINING = auto()
    LOCKED = auto()
    UNLOCKED = auto()


class LoginStatus(Enum):
    """Login status of Sesame."""

    UNLOGIN = auto()
    LOGIN = auto()


class ItemCodes(Enum):
    """Item codes used in Sesame command and notification payloads."""

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


class OpCodes(Enum):
    """Operation codes used in the header of received notifications."""

    CREATE = 0x01
    READ = 0x02
    UPDATE = 0x03
    DELETE = 0x04
    SYNC = 0x05
    ASYNC = 0x06
    RESPONSE = 0x07
    PUBLISH = 0x08
    UNDEFINE = 0x10


class ResultCodes(Enum):
    """Result codes received in response messages."""

    SUCCESS = 0
    INVALID_FORMAT = 1
    NOT_SUPPORTED = 2
    STORAGE_FAIL = 3
    INVALID_SIG = 4
    NOT_FOUND = 5
    UNKNOWN = 6
    BUSY = 7
    INVALID_PARAM = 8
