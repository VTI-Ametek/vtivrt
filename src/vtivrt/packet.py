'''Classes related to the parsing of VRT packets.'''
import struct
import math
from decimal import Decimal
from typing import Union, List
import pprint
import socket
try:
    import numpy
    _HAVE_NUMPY = True
except ImportError:
    _HAVE_NUMPY = False
from .constants import * # pylint: disable=wildcard-import,unused-wildcard-import

def _recvn(sock, num_bytes):
    buf = bytearray()
    while len(buf) < num_bytes:
        got = sock.recv(num_bytes-len(buf))
        if len(got) == 0:
            raise EOFError()
        buf += got
    return buf

class BitField():
    '''
A superclass representing a 32-bit integer broken into specific bit fields.
Subclasses should override _fields_ with a tuple such as:

.. code-block:: python

    class MyBitField(BitField):
        _fields_ = (
            ('foo', 24),
            ('bar', 8),
        )
This defines a MyBitField class with a "foo" field in the lower 24 bits,
and a "bar" field in the upper 8 bits.
    '''
    _fields_ = tuple()
    def __init__(self, word: bytes):
        self.decode(word)

    def decode(self, word: bytes):
        'Fill all fields from a :py:class:`bytes` representation of the bitfield'
        for name, width in self._fields_:
            if name:
                mask = (1 << width) - 1
                setattr(self, name, word & mask)
            word >>= width

    def __int__(self):
        word = 0
        for name, width in reversed(self._fields_):
            if name:
                word |= getattr(self, name)
            word <<= width
        return word

    def encode(self) -> bytes:
        'Returns a :py:class:`bytes` representation of the bitfield'
        return struct.pack('!I', int(self))

    def __str__(self):
        fields = []
        for name, _ in self._fields_:
            if name:
                fields.append(f'{name}={getattr(self, name)}')
        return f'{type(self).__name__}(word={hex(int(self))}, {", ".join(fields)})'

class VrtHeader(BitField): # pylint: disable=too-many-instance-attributes
    '''The header word of a VRT packet

:ivar size: (16 bits) The total number of 32-bit words in the packet, including this header word.
:ivar count: (4 bits) The 4-bit sequence number. This should increment separately for each combination of packet_type and stream_id.
:ivar tsf: (2 bits) The meaning of the fractional portion of the timestamp. Decode with :py:enum:`.constants.VrtTimestampFractional`.
:ivar tsi: (2 bits) The meaning of the integer portion of the timestamp. Decode with :py:enum:`.constants.VrtTimestampInteger`.
:ivar tsm: (1 bit) For context packets, indicates whether the timestamp is an exact match for the timestamp in the associated data packet's header (True) or instead represents the precise time of the events specified by the contents of the context packet (False).
:ivar has_trailer: (1 bit) 1 when a trailer word is included in the packet.
:ivar has_class: (1 bit) 1 when a 2-word class specifier is included in the packet.
:ivar packet_type: (4 bits) The packet type. Decode with :py:enum:`.constants.VrtPacketClass`.
'''
    _fields_ = (
        ('size', 16),
        ('count', 4),
        ('tsf', 2),
        ('tsi', 2),
        ('tsm', 1),
        (None, 1),
        ('has_trailer', 1),
        ('has_class', 1),
        ('packet_type', 4),
    )

class VrtTrailerFields(BitField):
    '''The trailer word of a VRT packet

:ivar context_count: (7 bits) The number of context packets associated with this data packet.
:ivar context_en: (1 bit) 1 when context data is enabled for this information stream.
:ivar indicators: (12 bits) The trailer flag indicators. Use :py:enum:`.constants.VrtTrailerEvents` to decode this value.
:ivar enables: (12 bits) The trailer flag enables. Use :py:enum:`.constants.VrtTrailerEvents` to decode this value. When a bit is 1, the corresponding bit in `indicators` is valid and should be read.
'''
    _fields_ = (
        ('context_count', 7),
        ('context_en', 1),
        ('indicators', 12),
        ('enables', 12),
    )

class VrtContextEvents(BitField):
    '''The events word of a VRT context packet

:ivar user_defined: (8 bits) The user defined event flags. Use :py:enum:`.constants.VrtMeasInfoUserEvent` to decode this value.
:ivar indicators: (12 bits) The event flag indicators. Use :py:enum:`.constants.VrtLogicalEvents` to decode this value.
:ivar enables: (12 bits) The event flag enables. Use :py:enum:`.constants.VrtLogicalEvents` to decode this value. When a bit is 1, the corresponding bit in `indicators` is valid and should be read.
'''
    _fields_ = (
        ('user_defined', 8),
        ('indicators', 12),
        ('enables', 12),
    )

class VtiVrtExMeasInfoSpanInfo(BitField):
    '''The span info word of an EXMeasInfo VRT context packet

:ivar filter: (4 bits) The selected filter type.
:ivar prescaler: (4 bits) The selected prescaler divisor.
:ivar span: (4 bits) The selected decimation span index.
'''
    _fields_ = (
        ('filter', 4),
        ('prescaler', 4),
        ('', 8),
        ('span', 4),
        ('', 8),
    )

class VtiVrtExMeasInfoRange(BitField):
    '''The range word of an EXMeasInfo VRT context packet. range = mantissa * 10^(exponent)

:ivar mantissa: (16 bits) The mantissa portion of the range value
:ivar exponent: (8 bits) The exponent portion of the range value, consisting of 1 bit of sign (1=negative) and 7 bits of magnitude.
'''
    _fields_ = (
        ('mantissa', 16),
        ('exponent', 8),
        ('', 8),
    )

class VtiVrtExMeasInfoEu(BitField):
    '''The EU conversion word of an EXMeasInfo VRT context packet

:ivar param_count: (8 bits) The number of EU Conversion parameter fields included.
:ivar eu_type: (8 bits) The tyep of EU conversion. Decode using :py:enum:`.constants.VtiVrtEuType`.
'''
    _fields_ = (
        ('param_count', 8),
        ('', 8),
        ('eu_type', 8),
        ('', 8),
    )

class VtiVrtExMeasInfoCommentInfo(BitField):
    '''The comment word of an EXMeasInfo VRT context packet

:ivar comment_id: (24 bits) The user-supplied comment-id.
:ivar comment_type: (8 bits) The comment type. Decode using :py:enum:`.constants.VtiVrtCommentType`.
'''
    _fields_ = (
        ('comment_id', 24),
        ('comment_type', 8),
    )

class VrtTrailer():
    '''Represents a VRT Packet Trailer word.

:ivar context_count: The number of context packets associated with this packet.
:ivar enables: If a flag is set in this mask, the corresponding bit in `indicators` is enabled and should be checked.
:ivar indicators: A mask representing various status conditions. Each flag is only valid if the corresponding bit in `enables` is set.
'''
    def __init__(self, context_count : int, enables : VrtTrailerEvents, indicators : VrtTrailerEvents):
        self.context_count = context_count
        self.enables = enables
        self.indicators = indicators

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'VrtTrailer(context_count={self.context_count}, enables={self.enables}, indicators={self.indicators})'

    @staticmethod
    def decode(word : int) -> 'VrtTrailer':
        '''Create a new :py:class:`VrtTrailer` from an unsigned 32-bit integer value.

:param word: The raw packet data, as an unsigned 32-bit integer.
'''
        trailer = VrtTrailerFields(word)
        enables = VrtTrailerEvents(trailer.enables)
        indicators = VrtTrailerEvents(trailer.indicators)

        if trailer.context_en:
            count = trailer.context_count
        else:
            count = None

        return VrtTrailer(count, enables, indicators)

    def encode(self) -> int:
        '''Convert the trailer back into the raw unsigned integer format.'''
        trailer = VrtTrailerFields(0)
        if self.context_count is not None:
            trailer.context_en = 1 # pylint: disable=attribute-defined-outside-init
            trailer.context_count = self.context_count # pylint: disable=attribute-defined-outside-init
        trailer.enables = int(self.enables) # pylint: disable=attribute-defined-outside-init
        trailer.indicators = int(self.indicators) # pylint: disable=attribute-defined-outside-init
        return int(trailer)

class VrtMeasInfoEvents():
    '''Represents the :py:attr:`events` field of a :py:class:`VtiVrtMeasInfoData` instance.

:ivar user_defined: A mask of user-defined event flags.
:ivar enables: If a flag is set in this mask, the corresponding bit in :py:attr:`indicators` is enabled and should be checked.
:ivar indicators: A mask representing various status conditions. Each flag is only valid if the corresponding bit in :py:attr:`enables` is set.
'''
    def __init__(self, user_defined : VrtMeasInfoUserEvent, enables : VrtLogicalEvents, indicators : VrtLogicalEvents):
        self.user_defined = user_defined
        self.enables = enables
        self.indicators = indicators

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'VrtMeasInfoEvents(user_defined={self.user_defined}, enables={self.enables}, indicators={self.indicators})'

    @staticmethod
    def decode(word : int) -> 'VrtMeasInfoEvents':
        '''Create a new :py:class:`VrtMeasInfoEvents` from an unsigned 32-bit integer value.

:param word: The raw packet data, as an unsigned 32-bit integer.
        '''
        event = VrtContextEvents(word)
        user = VrtMeasInfoUserEvent(event.user_defined)
        enables = VrtLogicalEvents(event.enables)
        indicators = VrtLogicalEvents(event.indicators)

        return VrtMeasInfoEvents(user, enables, indicators)

    def encode(self) -> int:
        '''Convert the trailer back into the raw unsigned integer format.'''
        trailer = VrtContextEvents(0)
        trailer.user_defined = int(self.user_defined) # pylint: disable=attribute-defined-outside-init
        trailer.enables = int(self.enables) # pylint: disable=attribute-defined-outside-init
        trailer.indicators = int(self.indicators) # pylint: disable=attribute-defined-outside-init
        return int(trailer)

class VtiVrtMeasInfoData():
    '''The VtiVrtMeasInfoData class represents the payload of the `VtiVrtPacketClass.MEAS_INFO` packet class.

:ivar indicators: This field contains flags to indicate whether any of the other attributes were included in the packet. Attributes whose associated indicator flag is not set will be None.
:ivar bandwidth: The input bandwidth of the channel.
:ivar reference_level: The reference level of the channel.
:ivar over_range_count: The number of samples in the associated packet that are over range.
:ivar sample_rate: The sample rate the data was measured at.
:ivar temperature: The current temperature of the measurement hardware.
:ivar events: The parsed value of the events word.
'''

    def __init__(self, indicators : VrtMeasInfoContextIndicator, bandwidth : float = None, reference_level : float = None, over_range_count : int = None, sample_rate : float = None, temperature : float = None, events : VrtMeasInfoEvents = None): # pylint: disable=too-many-arguments
        self.indicators = indicators
        self.bandwidth = bandwidth
        self.reference_level = reference_level
        self.over_range_count = over_range_count
        self.sample_rate = sample_rate
        self.temperature = temperature
        self.events = events

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'VtiVrtMeasInfoData(indicators={self.indicators}, ' + \
                                   'bandwidth={self.bandwidth}, ' + \
                                   'reference_level={self.reference_level}, ' + \
                                   'over_range_count={self.over_range_count}, ' + \
                                   'sample_rate={self.sample_rate}, ' + \
                                   'temperature={self.temperature}, ' + \
                                   'events={self.events})'

    def __len__(self):
        num_words = 1

        if VrtMeasInfoContextIndicator.BANDWIDTH in self.indicators:
            num_words += 2

        if VrtMeasInfoContextIndicator.REFERENCE_LEVEL in self.indicators:
            num_words += 1

        if VrtMeasInfoContextIndicator.OVER_RANGE_COUNT in self.indicators:
            num_words += 1

        if VrtMeasInfoContextIndicator.SAMPLE_RATE in self.indicators:
            num_words += 2

        if VrtMeasInfoContextIndicator.TEMPERATURE in self.indicators:
            num_words += 1

        if VrtMeasInfoContextIndicator.EVENTS in self.indicators:
            num_words += 1

        return num_words

    @staticmethod
    def decode(words:List[int]): # pylint: disable=too-many-branches
        '''Create a new instance of the :py:class:`VtiVrtMeasInfoData` class from a sequence unparsed payload data.

:param words: The payload data to be parsed. This should be formatted as a list of 32-bit unsigned integers.
        '''
        words = words[:]
        indicators = VrtMeasInfoContextIndicator(words.pop(0))

        if VrtMeasInfoContextIndicator.BANDWIDTH in indicators:
            val = words.pop(0) << 32
            val |= words.pop(0)
            val /= float(1<<20)
            bandwidth = val
        else:
            bandwidth = None

        if VrtMeasInfoContextIndicator.REFERENCE_LEVEL in indicators:
            reference_level = float(words.pop(0) & 0xffff) / float(1<<7)
        else:
            reference_level = None

        if VrtMeasInfoContextIndicator.OVER_RANGE_COUNT in indicators:
            over_range_count = words.pop(0)
        else:
            over_range_count = None

        if VrtMeasInfoContextIndicator.SAMPLE_RATE in indicators:
            val = words.pop(0) << 32
            val |= words.pop(0)
            val /= float(1<<20)
            sample_rate = val
        else:
            sample_rate = None

        if VrtMeasInfoContextIndicator.TEMPERATURE in indicators:
            temperature = float(words.pop(0) & 0xffff) / float(1<<6)
        else:
            temperature = None

        if VrtMeasInfoContextIndicator.EVENTS in indicators:
            events = VrtMeasInfoEvents.decode(words.pop(0))
        else:
            events = None

        if len(words) > 0:
            raise ValueError('VtiVrtMeasInfoData: got {len(words)} extra words')

        return VtiVrtMeasInfoData(indicators, bandwidth=bandwidth, reference_level=reference_level, over_range_count=over_range_count, sample_rate=sample_rate, temperature=temperature, events=events)

    def encode(self):
        '''Encode the context data as a list of 32-bit unsigned integers.'''
        words = [int(self.indicators)]

        if VrtMeasInfoContextIndicator.BANDWIDTH in self.indicators:
            val = int(self.bandwidth * float(1<<20))
            lo = val & 0xffffffff # pylint: disable=invalid-name
            hi = val >> 32 # pylint: disable=invalid-name
            words.append(hi)
            words.append(lo)

        if VrtMeasInfoContextIndicator.REFERENCE_LEVEL in self.indicators:
            words.append(int(self.reference_level * float(1<<7)))

        if VrtMeasInfoContextIndicator.OVER_RANGE_COUNT in self.indicators:
            words.append(self.over_range_count)

        if VrtMeasInfoContextIndicator.SAMPLE_RATE in self.indicators:
            val = int(self.sample_rate * float(1<<20))
            lo = val & 0xffffffff # pylint: disable=invalid-name
            hi = val >> 32 # pylint: disable=invalid-name
            words.append(hi)
            words.append(lo)

        if VrtMeasInfoContextIndicator.TEMPERATURE in self.indicators:
            words.append(int(self.temperature * float(1<<6)))

        if VrtMeasInfoContextIndicator.EVENTS in self.indicators:
            words.append(self.events.encode())

        return words

class VtiVrtExMeasInfoData(): # pylint: disable=too-many-instance-attributes
    '''The VtiVrtExMeasInfoData class represents the payload of the `VtiVrtPacketClass.EX_MEAS_INFO` packet class.

:ivar indicators: This field contains flags to indicate whether any of the other attributes were included in the packet. Attributes whose associated indicator flag is not set will be None.
:ivar span: Which stage of a series of divide-by-2 digital decimation filters the data was taken from.
:ivar prescaler: The divisor of the selected first stage digital decimation filter.
:ivar filter_: The filter type.
:ivar range_: The channel's nominal maximum input range.
:ivar weighting: The channel weighing.
:ivar eu_type: The type of EU conversion
:ivar eu_params: The list of EU conversion parameters. Interpretation depends on eu_type.
:ivar comment_type: The comment type.
:ivar comment_id: The user-supplied comment ID.
:ivar comment: The comment text.
:ivar trigger_timestamp: The timestamp of the trigger event that caused the associated data packet to be acquired.
:ivar reference_junction: A reference junction measurement value.
'''
    def __init__(self, indicators : VtiVrtExMeasInfoContextIndicator, span : int = None, prescaler : int = None, filter_ : int = None, # pylint: disable=too-many-arguments
                       range_ : float = None, weighting : VtiVrtWeighting = None, eu_type : VtiVrtEuType = None, eu_params : List[int] = None,
                       comment_type : VtiVrtCommentType = None, comment_id : int = None, comment : str = None, trigger_timestamp : Decimal = None, reference_junction : float = None):
        self.indicators = indicators
        self.span = span
        self.prescaler = prescaler
        self.filter_ = filter_
        self.range_ = range_
        self.weighting = weighting
        self.eu_type = eu_type
        self.eu_params = eu_params
        self.comment_type = comment_type
        self.comment_id = comment_id
        self.comment = comment
        self.trigger_timestamp = trigger_timestamp
        self.reference_junction = reference_junction

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f'''VtiVrtExMeasInfoData(indicators={str(self.indicators)},
                     span={self.span}, prescaler={self.prescaler}, filter_={self.filter_},
                     range_={self.range_}, weighting={self.weighting}, eu_type={self.eu_type}, eu_params={self.eu_params},
                     comment_type={self.comment_type}, comment_id={self.comment_id}, comment={self.comment},
                     trigger_timestamp={self.trigger_timestamp},
                     reference_junction={self.reference_junction})'''

    def __len__(self):
        num_words = 1

        if VtiVrtExMeasInfoContextIndicator.SPAN_PRESCALER_FILTER in self.indicators:
            num_words += 1

        if VtiVrtExMeasInfoContextIndicator.RANGE in self.indicators:
            num_words += 1

        if VtiVrtExMeasInfoContextIndicator.WEIGHTING in self.indicators:
            num_words += 1

        if VtiVrtExMeasInfoContextIndicator.EU in self.indicators:
            num_words += 1 + len(self.eu_params)

        if VtiVrtExMeasInfoContextIndicator.COMMENT in self.indicators:
            num_words += 2 + int(math.ceil(len(self.comment)/4.0))

        if VtiVrtExMeasInfoContextIndicator.TRIGGER_TIME in self.indicators:
            num_words += 3

        if VtiVrtExMeasInfoContextIndicator.REFERENCE_JUNCTION in self.indicators:
            num_words += 1

        return num_words

    @staticmethod
    def decode(words): # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        '''Create a new instance of the `VtiVrtExMeasInfoData` class from a sequence unparsed payload data.

:param words: The payload data to be parsed. This should be formatted as a list of 32-bit unsigned integers.
'''
        words = words[:]
        indicators = VtiVrtExMeasInfoContextIndicator(words.pop(0))

        if VtiVrtExMeasInfoContextIndicator.SPAN_PRESCALER_FILTER in indicators:
            vals = VtiVrtExMeasInfoSpanInfo(words.pop(0))
            span = vals.span
            prescaler = vals.prescaler
            filter_ = vals.filter
        else:
            span = None
            prescaler = None
            filter_ = None

        if VtiVrtExMeasInfoContextIndicator.RANGE in indicators:
            vals = VtiVrtExMeasInfoRange(words.pop(0))
            # exponent is 8-bit signed power of 10
            exp = vals.exponent
            if exp & 0x80:
                exp -= 0x100
            range_ = vals.mantissa * math.pow(10, exp)
        else:
            range_ = None

        if VtiVrtExMeasInfoContextIndicator.WEIGHTING in indicators:
            weighting = VtiVrtWeighting(words.pop(0) & 0xff)
        else:
            weighting = None

        if VtiVrtExMeasInfoContextIndicator.EU in indicators:
            vals = VtiVrtExMeasInfoEu(words.pop(0))
            eu_type = VtiVrtEuType(vals.eu_type)
            eu_params = [words.pop(0) for _ in range(vals.param_count)]
        else:
            eu_type = None
            eu_params = None

        if VtiVrtExMeasInfoContextIndicator.COMMENT in indicators:
            vals = VtiVrtExMeasInfoCommentInfo(words.pop(0))
            comment_id = vals.comment_id
            comment_type = VtiVrtCommentType(vals.comment_type)
            nwords = words.pop(0) & 0xffff
            comment_words = [words.pop(0) for _ in range(nwords)]
            comment = struct.pack(f'>{nwords}I', *comment_words).decode('utf-8').strip('\x00')
        else:
            comment_id = None
            comment_type = None
            comment = None

        if VtiVrtExMeasInfoContextIndicator.TRIGGER_TIME in indicators:
            trigger_timestamp = Decimal(words.pop(0))
            picoseconds = words.pop(0) << 32
            picoseconds |= words.pop(0)
            trigger_timestamp += picoseconds / PICO_DIVISOR
        else:
            trigger_timestamp = None

        if VtiVrtExMeasInfoContextIndicator.REFERENCE_JUNCTION in indicators:
            reference_junction, = struct.unpack('f', struct.pack('I', words.pop(0)))
        else:
            reference_junction = None

        if len(words) > 0:
            raise ValueError(f'VtiVrtExMeasInfoData: got {len(words)} extra words')

        return VtiVrtExMeasInfoData(
            indicators=indicators, span=span, prescaler=prescaler, filter_=filter_,
            range_=range_, weighting=weighting, eu_type=eu_type, eu_params=eu_params,
            comment_type=comment_type, comment_id=comment_id, comment=comment, trigger_timestamp=trigger_timestamp, reference_junction=reference_junction
        )

    def encode(self):
        '''Encode the context data as a list of 32-bit unsigned integers.'''
        words = [int(self.indicators)]

        if VtiVrtExMeasInfoContextIndicator.SPAN_PRESCALER_FILTER in self.indicators:
            vals = VtiVrtExMeasInfoSpanInfo(0)
            vals.span = self.span # pylint: disable=attribute-defined-outside-init
            vals.prescaler = self.prescaler # pylint: disable=attribute-defined-outside-init
            vals.filter = self.filter_ # pylint: disable=attribute-defined-outside-init
            words.append(int(vals))

        if VtiVrtExMeasInfoContextIndicator.RANGE in self.indicators:
            vals = VtiVrtExMeasInfoRange(0)
            mantissa = self.range_
            exp = 0
            while int(mantissa) != mantissa and mantissa < ((1<<16)/10):
                mantissa *= 10
                exp -= 1
            while mantissa > (1<<16):
                mantissa /= 10
                exp += 1
            vals.exponent = exp # pylint: disable=attribute-defined-outside-init
            vals.mantissa = mantissa # pylint: disable=attribute-defined-outside-init
            words.append(int(vals))

        if VtiVrtExMeasInfoContextIndicator.WEIGHTING in self.indicators:
            words.append(int(self.weighting))

        if VtiVrtExMeasInfoContextIndicator.EU in self.indicators:
            vals = VtiVrtExMeasInfoEu(0)
            vals.eu_type = int(self.eu_type) # pylint: disable=attribute-defined-outside-init
            vals.param_count = len(self.eu_params) # pylint: disable=attribute-defined-outside-init
            words.append(vals)
            words.extend(self.eu_params)

        if VtiVrtExMeasInfoContextIndicator.COMMENT in self.indicators:
            vals = VtiVrtExMeasInfoCommentInfo(0)
            vals.comment_id = self.comment_id # pylint: disable=attribute-defined-outside-init
            vals.comment_type = int(self.comment_type) # pylint: disable=attribute-defined-outside-init
            words.append(int(vals))
            buf = self.comment.encode('utf-8')
            pad = len(buf) % 4
            if pad:
                buf = buf + b'\x00' * (4 - pad)
            words.extend(struct.unpack(f'!{len(buf) / 4}I', buf))

        if VtiVrtExMeasInfoContextIndicator.TRIGGER_TIME in self.indicators:
            sec = int(self.trigger_timestamp)
            pico = int((self.trigger_timestamp - sec) * PICO_DIVISOR)
            words.append(sec)
            words.append(pico >> 32)
            words.append(pico & 0xffffffff)

        if VtiVrtExMeasInfoContextIndicator.REFERENCE_JUNCTION in self.indicators:
            words.extend(struct.unpack('I', struct.pack('f', self.reference_junction)))

        return words

class VtiVrtPacket(): # pylint: disable=too-many-instance-attributes
    '''Represents one VRT packet.

:ivar stream_id: The unique numerical identifier of this data stream.
:ivar count: The 4-bit sequence number. This should increment separately for each combination of packet_type and stream_id.
:ivar packet_type: The packet type.
:ivar tsi: The meaning of the integer portion of the timestamp.
:ivar tsf: The meaning of the fractional portion of the timestamp.
:ivar tsm: For context packets, indicates whether the timestamp is an exact match for the timestamp in the associated data packet's header (True) or instead represents the precise time of the events specified by the contents of the context packet (False).
:ivar timestamp: The value of the timestamp fields.
:ivar oui: The IANI OUI of the vendor of the product that created this packet. Should always be equal to `VTI_OUI` for VTI products.
:ivar info_class: The class of the information stream that this packet belongs to.
:ivar packet_class: The class of the packet.
:ivar data: The payload of the packet.
:ivar trailer: The parsed information from the packet trailer.
:ivar context: The context packets associated with this packet.
'''
    def __init__(self, stream_id : int, count : int, packet_type : VrtPacketType, tsi : VrtTimestampInteger, tsf : VrtTimestampFractional, tsm : bool, timestamp : Decimal = None, oui : int = None, info_class : VtiVrtInfoClass = None, packet_class : VtiVrtPacketClass = None, data : Union[List[float], List[int], VtiVrtMeasInfoData, VtiVrtExMeasInfoData] = None, trailer : VrtTrailer = None, context : List['VtiVrtPacket'] = None): # pylint: disable=too-many-arguments
        self.stream_id = stream_id
        self.count = count
        self.packet_type = packet_type
        self.tsi = tsi
        self.tsf = tsf
        self.tsm = tsm
        self.timestamp = timestamp
        self.oui = oui
        self.info_class = info_class
        self.packet_class = packet_class
        if data is None:
            self.data = []
        else:
            self.data = data
        self.trailer = trailer
        if context is None:
            self.context = []
        else:
            self.context = context

    def __repr__(self):
        return f'''VtiVrtPacket(stream_id={self.stream_id}, count={self.count}, packet_type={str(self.packet_type)},
             tsi={str(self.tsi)}, tsf={str(self.tsf)}, tsm={self.tsm}, timestamp={self.timestamp},
             oui={hex(self.oui) if self.oui is not None else None}, info_class={str(self.info_class) if self.info_class is not None else None}, packet_class={str(self.packet_class) if self.packet_class is not None else None},
             data={pprint.pformat(self.data, compact=True)},
             trailer={pprint.pformat(self.trailer, compact=True)},
             context={pprint.pformat(self.context, compact=True)})'''

    def encode(self, binary_point : int = None) -> bytearray: # pylint: disable=too-many-locals,too-many-statements,too-many-branches
        '''Encode the packet as a bytearray suitable for writing to a socket.

:param binary_point: If specified, and if the packet is a data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
'''
        context = b''
        if self.context:
            for packet in self.context:
                context += packet.encode()
        header = VrtHeader(0)
        header.packet_type = int(self.packet_type) # pylint: disable=attribute-defined-outside-init
        header.has_class = None not in (self.oui, self.info_class, self.packet_class) # pylint: disable=attribute-defined-outside-init
        header.tsm = int(self.tsm) # pylint: disable=attribute-defined-outside-init
        header.tsf = int(self.tsf) # pylint: disable=attribute-defined-outside-init
        header.tsi = int(self.tsi) # pylint: disable=attribute-defined-outside-init
        header.has_trailer = self.trailer is not None # pylint: disable=attribute-defined-outside-init
        header.count = self.count # pylint: disable=attribute-defined-outside-init
        header.size = len(self.data) # pylint: disable=attribute-defined-outside-init
        if header.has_class:
            header.size += 2
        if self.tsi != VrtTimestampInteger.NONE:
            header.size += 1
        if self.tsf != VrtTimestampFractional.NONE:
            header.size += 2
        if header.has_trailer:
            header.size += 1

        buf = bytearray()
        buf += struct.pack('!I', int(header))
        buf += struct.pack('!I', self.stream_id)
        if header.has_class:
            buf += struct.pack('!IHH', self.oui, int(self.info_class), int(self.packet_class))
        sec = int(self.timestamp)
        pico = int((self.timestamp - sec) * PICO_DIVISOR)
        if self.tsi != VrtTimestampInteger.NONE:
            buf += struct.pack('!I', sec)
        if self.tsf != VrtTimestampFractional.NONE:
            buf += struct.pack('!Q', pico)

        data = self.data
        if self.packet_type == VrtPacketType.IF_CONTEXT:
            if self.packet_class == VtiVrtPacketClass.MEAS_INFO:
                data = data.encode()
        elif self.packet_type == VrtPacketType.EXT_CONTEXT:
            if self.packet_class == VtiVrtPacketClass.EX_MEAS_INFO:
                data = data.encode()
        elif self.packet_type in (VtiVrtInfoClass.SINGLE_SPAN_INT32,
                                  VtiVrtInfoClass.MULTI_SPAN_INT32,
                                  VtiVrtInfoClass.SINGLE_SPAN_FREQ_INT32,
                                  VtiVrtInfoClass.MULTI_SPAN_FREQ_INT32,
                                  VtiVrtInfoClass.SINGLE_OCTAVE_INT32,
                                  VtiVrtInfoClass.THIRD_OCTAVE_INT32):
            if self.packet_class in (VtiVrtPacketClass.MEAS_INT32,
                                     VtiVrtPacketClass.FREQ_INT32,
                                     VtiVrtPacketClass.SINGLE_OCTAVE_INT32,
                                     VtiVrtPacketClass.THIRD_OCTAVE_INT32) and binary_point is not None:
                div = float(1 << binary_point)
                if _HAVE_NUMPY:
                    data = list(numpy.array(data) * div)
                else:
                    data = [x * div for x in data]

        if self.packet_class == VtiVrtPacketClass.MEAS_FLOAT32:
            typ = 'f'
        elif self.packet_type in (VrtPacketType.IF_CONTEXT, VrtPacketType.EXT_CONTEXT):
            typ = 'I'
        else:
            typ = 'i'
        buf += struct.pack(f'!{len(data)}{typ}', *data)

        if header.has_trailer:
            buf += struct.pack('!I', self.trailer.encode())

        return context + buf

    def to_socket(self, sock, binary_point = None) -> None:
        '''Write the packet to the supplied socket

:param sock: The socket to read the packet from.
:param binary_point: If specified, and if the packet is a data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
'''
        sock.send(self.encode(binary_point))

    @staticmethod
    def from_socket(sock: socket.socket, binary_point : int = None) -> 'VtiVrtPacket': # pylint: disable=too-many-locals
        '''Read data from the supplied socket, and constrct a new VtiVrtPacket from it.

:param sock: The socket to read the packet from.
:param binary_point: If specified, and if the packet is a data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
'''
        header, stream_id = struct.unpack('!II', _recvn(sock, 8))
        header = VrtHeader(header)

        packet_type = VrtPacketType(header.packet_type)
        tsi = VrtTimestampInteger(header.tsi)
        tsf = VrtTimestampFractional(header.tsf)

        overhead = 2

        oui = None
        info_class = None
        packet_class = None
        if header.has_class:
            oui, info_class, packet_class = struct.unpack('!IHH', _recvn(sock, 8))
            info_class = VtiVrtInfoClass(info_class)
            packet_class = VtiVrtPacketClass(packet_class)
            overhead += 2

        seconds = None
        if tsi != VrtTimestampInteger.NONE:
            seconds, = struct.unpack('!I', _recvn(sock, 4))
            overhead += 1

        picoseconds = None
        if tsf != VrtTimestampFractional.NONE:
            val, = struct.unpack('!Q', _recvn(sock, 8))
            overhead += 2
            if tsf == VrtTimestampFractional.REAL:
                picoseconds = val

        if seconds is None:
            if picoseconds is None:
                timestamp = None
            else:
                timestamp = picoseconds / PICO_DIVISOR
        else:
            timestamp = Decimal(seconds)
            if picoseconds is not None:
                timestamp += picoseconds / PICO_DIVISOR

        if header.has_trailer:
            overhead += 1

        data = VtiVrtPacket.parse_data(sock, header.size - overhead, packet_type, packet_class, binary_point)

        trailer = None
        if header.has_trailer:
            trailer = VrtTrailer.decode(struct.unpack('!I', _recvn(sock, 4))[0])

        return VtiVrtPacket(stream_id, header.count, packet_type, tsi, tsf, bool(header.tsm), timestamp, oui, info_class, packet_class, data, trailer)

    @staticmethod
    def parse_data(sock: socket.socket, samples: int, packet_type: VrtPacketType, packet_class: VtiVrtPacketClass, binary_point: int = None):
        '''Parse the data portion of a VRT packet from the supplied socket.

:param sock: The socket to read the packet from.
:param samples: The size of the data portion, in samples.
:param packet_type: The packet type field from the header
:param packet_class: The packet class field
:param binary_point: If specified, and if the packet is a data packet with an integer data type, the data samples will be interpretted as fixed-point, with a fractional portion the size of this value, in bits.
'''
        data = _recvn(sock, 4 * samples)
        if packet_class == VtiVrtPacketClass.MEAS_FLOAT32:
            typ = 'f'
        elif packet_type in (VrtPacketType.IF_CONTEXT, VrtPacketType.EXT_CONTEXT):
            typ = 'I'
        else:
            typ = 'i'
        data = list(struct.unpack(f'!{samples}{typ}', data))
        if packet_type == VrtPacketType.IF_CONTEXT:
            if packet_class == VtiVrtPacketClass.MEAS_INFO:
                data = VtiVrtMeasInfoData.decode(data)
        elif packet_type == VrtPacketType.EXT_CONTEXT:
            if packet_class == VtiVrtPacketClass.EX_MEAS_INFO:
                data = VtiVrtExMeasInfoData.decode(data)
        elif packet_type in (VtiVrtInfoClass.SINGLE_SPAN_INT32,
                             VtiVrtInfoClass.MULTI_SPAN_INT32,
                             VtiVrtInfoClass.SINGLE_SPAN_FREQ_INT32,
                             VtiVrtInfoClass.MULTI_SPAN_FREQ_INT32,
                             VtiVrtInfoClass.SINGLE_OCTAVE_INT32,
                             VtiVrtInfoClass.THIRD_OCTAVE_INT32):
            if packet_class in (VtiVrtPacketClass.MEAS_INT32,
                                VtiVrtPacketClass.FREQ_INT32,
                                VtiVrtPacketClass.SINGLE_OCTAVE_INT32,
                                VtiVrtPacketClass.THIRD_OCTAVE_INT32) and binary_point is not None:
                div = float(1 << binary_point)
                if _HAVE_NUMPY:
                    data = list(numpy.array(data) / div)
                else:
                    data = [x / div for x in data]

        return data
