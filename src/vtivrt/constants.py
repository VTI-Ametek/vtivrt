'''Constants and enumerations for vtivrt.

The types prefixed as just "Vrt" are defined as part of VITA 49. Those prefixed as "VtiVrt" are defined by VTI Instruments.'''
# pylint: disable=missing-class-docstring
import enum
from decimal import Decimal

VTI_OUI: int = 0x0003df
VTI_STREAM_GREETING: bytes = '1400 stream\n'.encode('ascii')
PICO_DIVISOR: Decimal = Decimal(1000000000000)

@enum.unique
class VtiVrtInfoClass(enum.IntEnum):
    'The VRT Information Class'
    SINGLE_SPAN_INT32 = 1
    MULTI_SPAN_INT32 = 2
    SINGLE_SPAN_FREQ_INT32 = 3
    MULTI_SPAN_FREQ_INT32 = 4
    SINGLE_OCTAVE_INT32 = 5
    THIRD_OCTAVE_INT32 = 6
    TIMESTAMP_INT32 = 7
    SYSTEM_CONTEXT = 8
    SINGLE_SPAN_FLOAT32 = 9

@enum.unique
class VtiVrtPacketClass(enum.IntEnum):
    'The VRT Packet Class'
    MEAS_INT32 = 1
    MEAS_INFO = 2
    EX_MEAS_INFO = 3
    FREQ_INT32 = 4
    REAL_FREQ_INT32 = 5
    FREQ_INFO = 6
    SINGLE_OCTAVE_INT32 = 7
    THIRD_OCTAVE_INT32 = 8
    OCTAVE_INFO = 9
    TIMESTAMP_INT32 = 10
    TACH_INFO = 11
    MFUNC_INFO = 12
    MEAS_FLOAT32 = 13

@enum.unique
class VrtPacketType(enum.IntEnum):
    'The VRT Packet Type field'
    IF_DATA_NO_ID = 0
    IF_DATA_WITH_ID = 1
    EXT_DATA_NO_ID = 2
    EXT_DATA_WITH_ID = 3
    IF_CONTEXT = 4
    EXT_CONTEXT = 5

@enum.unique
class VrtTimestampInteger(enum.IntEnum):
    'The VRT Timestamp Integer field'
    NONE = 0
    UTC = 1
    GPS = 2
    OTHER = 3

@enum.unique
class VrtTimestampFractional(enum.IntEnum):
    'The VRT Timestamp Fractional field'
    NONE = 0
    COUNT = 1
    REAL = 2
    FREE = 3

@enum.unique
class VrtTrailerEvents(enum.IntFlag):
    'The VRT measurement packet trailer flags'
    USER1 = 1<<0
    USER2 = 1<<1
    USER3 = 1<<2
    USER4 = 1<<3
    SAMPLE_LOSS = 1<<4
    OVER_RANGE = 1<<5
    SPECTRAL_INVERSION = 1<<6
    DETECTED_SIGNAL = 1<<7
    AGC_MGC = 1<<8
    REFERENCE_LOCK = 1<<9
    VALID_DATA = 1<<10
    CALIBRATED_TIME = 1<<11

@enum.unique
class VtiVrtWeighting(enum.IntEnum):
    '''The possible values of the Extended Context packet's Weighting field'''
    NONE = 0
    A = 1
    B = 2
    C = 3

@enum.unique
class VrtMeasInfoContextIndicator(enum.IntFlag):
    '''The VRT Measurement Info Context packet's Context Indicator flags'''
    FIELD_CHANGED    = 0x80000000
    BANDWIDTH        = 0x20000000
    REFERENCE_LEVEL  = 0x01000000
    OVER_RANGE_COUNT = 0x00400000
    SAMPLE_RATE      = 0x00200000
    TEMPERATURE      = 0x00040000
    EVENTS           = 0x00010000

@enum.unique
class VtiVrtExMeasInfoContextIndicator(enum.IntFlag):
    '''The Extended Measurement Info Context packet's Context Indicator flags'''
    FIELD_CHANGED         = 0x80000000
    SPAN_PRESCALER_FILTER = 0x40000000
    RANGE                 = 0x20000000
    WEIGHTING             = 0x10000000
    EU                    = 0x08000000
    COMMENT               = 0x04000000
    TRIGGER_TIME          = 0x02000000
    REFERENCE_JUNCTION    = 0x01000000

@enum.unique
class VrtMeasInfoUserEvent(enum.IntFlag):
    '''The VRT Measurement Info Context packet's User Event field flags'''
    RESAMPLING = 0x80
    FIFO_OVERFLOW = 0x08
    DROPPED_TRIG = 0x04
    INIT = 0x02
    DATA_STREAM = 0x01

@enum.unique
class VtiVrtEuType(enum.IntEnum):
    '''The Extended Measurement Info Context packet's EU Conversion Type field'''
    RAW = 0
    UNIT_SCALE = 1
    LINEAR_SCALE = 2
    USER_POLYNOMIAL = 3

@enum.unique
class VtiVrtCommentType(enum.IntEnum):
    '''The Extended Measurement Info Context packet's Comment Type field'''
    USER = 0

@enum.unique
class VrtLogicalEvents(enum.IntFlag):
    '''The VRT Measurement Info Context packet's Event Enables and Indicators fields' flags'''
    SAMPLE_LOSS = 1<<4
    OVER_RANGE = 1<<5
    SPECTRAL_INV = 1<<6
    DETECTED_SIG = 1<<7
    AGC_MGC = 1<<8
    REF_LOCK = 1<<9
    VALID_DATA = 1<<10
    CALIB_TIME = 1<<11
