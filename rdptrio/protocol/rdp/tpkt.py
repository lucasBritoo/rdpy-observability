#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Transport packet layer implementation

Use to build correct size packet and handle slow path and fast path mode
"""
# from rdptrio.core.layer import RawLayer
from rdptrio.core.type import UInt8,UInt16Be#, UInt16Le, #, sizeof
import logging
import struct
# import sys
# import struct
# from rdpy.core.error import CallPureVirtualFuntion

logger = logging.getLogger(__name__)
from rdptrio.core.config import Config

config = Config('rdptrio/config/gcc.yaml')
# logger.setLevel(logging.DEBUG)

# class Action(object):
#     """
#     @see: http://msdn.microsoft.com/en-us/library/cc240621.aspx
#     @see: http://msdn.microsoft.com/en-us/library/cc240589.aspx
#     """
#     FASTPATH_ACTION_FASTPATH = 0x0
#     FASTPATH_ACTION_X224 = 0x3
    
# class SecFlags(object):
#     """
#     @see: http://msdn.microsoft.com/en-us/library/cc240621.aspx
#     """
#     #hihi 'secure' checksum but private key is public !!!
#     FASTPATH_OUTPUT_SECURE_CHECKSUM = 0x1
#     FASTPATH_OUTPUT_ENCRYPTED = 0x2

# class IFastPathListener(object):
#     """
#     @summary:  Fast path packet listener
#                 Usually X224 layer
#     """
#     def recvFastPath(self, secFlag, fastPathS):
#         """
#         @summary: Call when fast path packet is received
#         @param secFlag: {SecFlags}
#         @param fastPathS: {Stream}
#         """
#         raise ValueError("%s:%s defined by interface %s"%(self.__class__, "recvFastPath", "IFastPathListener"))
        
#         # raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "recvFastPath", "IFastPathListener"))
    
#     def initFastPath(self, fastPathSender):
#         """
#         @summary: initialize stack
#         @param fastPathSender: {IFastPathSender}
#         """
#         logger.debug('[TPKT/IFastPathListener/initFastPath]')
#         self.setFastPathSender(fastPathSender)
#         fastPathSender.setFastPathListener(self)
    
# class IFastPathSender(object):
#     """
#     @summary: Fast path send capability
#     """
#     def sendFastPath(self, secFlag, fastPathS):
#         """
#         @summary: Send fastPathS Type as fast path packet
#         @param secFlag: {integer} Security flag for fastpath packet
#         @param fastPathS: {Type | Tuple} type transform to stream and send as fastpath
#         """
#         raise ValueError("%s:%s defined by interface %s"%(self.__class__, "sendFastPath", "IFastPathSender"))
        
#         # raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "sendFastPath", "IFastPathSender"))
    
#     def initFastPath(self, fastPathListener):
#         """
#         @summary: initialize stack
#         @param fastPathListener: {IFastPathListener}
#         """
#         self.setFastPathListener(fastPathListener)
#         fastPathListener.setFastPathSender(self)
        
#     def setFastPathListener(self, fastPathListener):
#         """
#         @param fastPathListener: {IFastPathListener}
#         """
#         raise ValueError("%s:%s defined by interface %s"%(self.__class__, "setFastPathListener", "IFastPathSender"))
        
#         # raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "setFastPathListener", "IFastPathSender"))

class ConfigTPKT():
   
    def __init__(self):
        self.VERSION= 0x03
        self.RESERVED= 0x00

class TPKT():#RawLayer, IFastPathSender):
    """
    @summary:  TPKT layer in RDP protocol stack
                represent the Raw Layer in stack (first layer)
                This layer only handle size of packet and determine if is a fast path packet
    """
    def __init__(self, x224Layer):
        """
        @param presentation: {Layer} presentation layer, in RDP case is x224 layer
        """
        logger.debug('[TPKT]')

        #fast path listener
        self._x224Layer = x224Layer
        self._version = UInt8(ConfigTPKT().VERSION, "version")
        self._reserved = UInt8(ConfigTPKT().RESERVED, "reserved")
    
    def getHeader(self):

        return [self._version, self._reserved, self._x224Layer]
    
    def getHeaderSize(self):
        
        _size = 0

        for attribute in self.getHeader():
            _size += attribute._size
        
        return (_size + 2)
    
    def getPacket(self):
        size = UInt16Be(self.getHeaderSize(), "sizeTPKT")
        logger.debug(f"TPKT Header size: {size._value}")
        return [self._version, self._reserved, size, self._x224Layer]

    def readHeader(self, message):
        
        buffer = bytearray(message)
        
        tpktFormat = '>BBH'

        tpktHeader = bytearray(struct.calcsize(tpktFormat))
        tpktHeader = struct.unpack(tpktFormat, buffer[:struct.calcsize(tpktFormat)])
        
        tpktClass, tpktReserved, tpktLenght = tpktHeader
        
        logger.debug(f'TPKT Class: {tpktClass:02X}')
        logger.debug(f'TPKT Reserved: {tpktReserved:02X}')
        logger.debug(f'TPKT Lenght: {tpktLenght:04X}')
        
        x224Format = '>BBHHBBBHI'
        
        x224Header = bytearray(struct.calcsize(x224Format))
        x224Header = struct.unpack(x224Format, buffer[struct.calcsize(tpktFormat):struct.calcsize(tpktFormat) + struct.calcsize(x224Format)])
        
        x224Lenght, x224CCCDT, x224DSTref, x224SRCref, x224Classopt, x224NegType, x224NegFlag, x224NegLenght, x224NegProtocol = x224Header 
        logger.debug(f'X224 Lengh: {x224Lenght:02X}')
        logger.debug(f'X224 CC/CDT: {x224CCCDT:02X}')
        logger.debug(f'x224 DST/REF: {x224DSTref:04X}')
        logger.debug(f'X224 SRC/REF: {x224SRCref:04X}')
        logger.debug(f'X224 Class Opt: {x224Classopt:02X}')
        logger.debug(f'X224 Neg Type: {x224NegType:02X}')
        logger.debug(f'X224 Neg Flag: {x224NegFlag:02X}')
        logger.debug(f'X224 Neg Lenght: {x224NegLenght:04X}')
        logger.debug(f'X224 Neg Protocol: {x224NegProtocol:08X}')
        
        # x224Header = bytearray()
        # if buffer[0].to_bytes(1, byteorder='big') == self._version._value:
        #     packetSize = buffer[3]
        #     packetX224 = buffer[5:5 + packetSize]
        #     packetX224Size = buffer[4]

        #     # Defina o formato do cabeçalho X224 usando struct
        #     x224_format = ">BBHHBBHII"
        #     header_values = bytearray(packetX224Size)
        #     logger.debug(f"Teste Size: {header_values}")
        #     header_values = struct.unpack(x224_format, packetX224)

        #     # Descompacte os valores e atribua às variáveis
        #     headerX224_connectionConfirm, \
        #     headerX224_reserved, \
        #     headerX224_destinationReference, \
        #     headerX224_sourceReference, \
        #     headerX224_classOption, \
        #     headerX224_typeConfirm, \
        #     headerX224_flagConfirm, \
        #     headerX224_length, \
        #     headerX224_code = header_values

        #     logger.debug(f"PacketX224 Len: {len(packetX224)}")
        #     logger.debug(f"PacketX224 Confirm: {headerX224_connectionConfirm:02X}")
        #     logger.debug(f"PacketX224 Destination: {headerX224_destinationReference}")
        #     logger.debug(f"PacketX224 Source: {headerX224_sourceReference}")
        #     logger.debug(f"PacketX224 Class: {headerX224_classOption:02X}")
        #     logger.debug(f"PacketX224 Type: {headerX224_typeConfirm:02X}")
        #     logger.debug(f"PacketX224 Flag: {headerX224_flagConfirm:02X}")
        #     logger.debug(f"PacketX224 Length: {headerX224_length}")
        #     logger.debug(f"PacketX224 Code: {headerX224_code}")
            
            
            

        # logger.debug(f"Output TPKT Version: {buffer[0]}")
        # logger.debug(f"TPKT Version: {self._version._value}")
        # logger.debug(f"Output TPKT Reserved: {buffer[1]:02X}{buffer[2]:02X}")
        # logger.debug(f"Output TPKT Size: {buffer[3]:02X}")
                
    # def getPacketSize(self):
        
    #     _headerSize = self.getHeaderSize()
    #     _packetSize = struct.unpack(_headerSize._structFormat, _headerSize._value)[0]
  
    #     return (_headerSize._size + _packetSize)
    
        # return UInt8(_size)
        # logger.debug(f"X224: {self._packageX224}")
        
        # packedHeaderFormat = f"{self._version._structFormat}{self._reserved._structFormat}{self._packageX224Format}"
        # packedHeader = struct.pack(
        #     packedHeaderFormat,
        #     self._version._value,
        #     self._reserved._value,
        #     self._packageX224
        # )
        
        # self.lenTPKT = UInt16Be(len(packedHeader))
        
        # packedTPKTFormat = f"{self._version._structFormat}{self._reserved._structFormat}{self.lenTPKT._structFormat}{self._packageX224Format}"
        # packedTPKT = struct.pack(
        #     packedTPKTFormat,
        #     self._version._value,
        #     self._reserved._value,
        #     self.lenTPKT._value,
        #     self._packageX224
        # )
        # packageTPKT = (
        #     self._version._value +
        #     self._reserved._value +
        #     self.lenTPKT._value +
        #     self._packageX224
        # )
        
        # logger.debug(f"Header: {self._version._value + self._reserved._value}")
        
    # def setFastPathListener(self, fastPathListener):
    #     """
    #     @param fastPathListener : {IFastPathListener}
    #     @note: implement IFastPathSender
    #     """
    #     self._fastPathListener = fastPathListener
        
    # def connect(self):
    #     """
    #     @summary:  Call when transport layer connection
    #                 is made (inherit from RawLayer)
    #     """
    #     #header is on two bytes
    #     self.expect(2, self.readHeader)
    #     #no connection automata on this layer
    #     if not self._presentation is None:
    #         self._presentation.connect()
        
    # def readHeader(self, data):
    #     """
    #     @summary: Read header of TPKT packet
    #     @param data: {Stream} received from twisted layer
    #     """
    #     #first read packet version
    #     version = UInt8()
    #     data.readType(version)
    #     #classic packet
    #     if version.value == Action.FASTPATH_ACTION_X224:
    #         #padding
    #         data.readType(UInt8())
    #         #read end header
    #         self.expect(2, self.readExtendedHeader)
    #     else:
    #         #is fast path packet
    #         self._secFlag = ((version.value >> 6) & 0x3)
    #         data.readType(self._lastShortLength)
    #         if self._lastShortLength.value & 0x80:
    #             #size is 1 byte more
    #             self.expect(1, self.readExtendedFastPathHeader)
    #             return
    #         self.expect(self._lastShortLength.value - 2, self.readFastPath)
                
    # def readExtendedHeader(self, data):
    #     """
    #     @summary: Header may be on 4 bytes
    #     @param data: {Stream} from twisted layer
    #     """
    #     #next state is read data
    #     size = UInt16Be()
    #     data.readType(size)
    #     self.expect(size.value - 4, self.readData)
    
    # def readExtendedFastPathHeader(self, data):
    #     """
    #     @summary: Fast path header may be on 1 byte more
    #     @param data: {Stream} from twisted layer
    #     """
    #     leftPart = UInt8()
    #     data.readType(leftPart)
    #     self._lastShortLength.value &= ~0x80
    #     packetSize = (self._lastShortLength.value << 8) + leftPart.value
    #     #next state is fast patn data
    #     self.expect(packetSize - 3, self.readFastPath)
    
    # def readFastPath(self, data):
    #     """
    #     @summary: Fast path data
    #     @param data: {Stream} from twisted layer
    #     """
    #     self._fastPathListener.recvFastPath(self._secFlag, data)
    #     self.expect(2, self.readHeader)
    
    # def readData(self, data):
    #     """
    #     @summary: Read classic TPKT packet, last state in tpkt automata
    #     @param data: {Stream} with correct size
    #     """
    #     #next state is pass to 
    #     self._presentation.recv(data)
    #     self.expect(2, self.readHeader)
        
    # def send(self, message):
    #     """
    #     @summary: Send encompassed data
    #     @param message: {network.Type} message to send
    #     """
    #     logger.debug(f"[TPKT/send]")
    #     RawLayer.send(self, (UInt8(Action.FASTPATH_ACTION_X224), UInt8(0), UInt16Be(sizeof(message) + 4), message))
        
    # def sendFastPath(self, secFlag, fastPathS):
    #     """
    #     @param fastPathS: {Type | Tuple} type transform to stream and send as fastpath
    #     @param secFlag: {integer} Security flag for fastpath packet
    #     """
    #     RawLayer.send(self, (UInt8(Action.FASTPATH_ACTION_FASTPATH | ((secFlag & 0x3) << 6)), UInt16Be((sizeof(fastPathS) + 3) | 0x8000), fastPathS))
    
    # def startTLS(self, sslContext):
    #     """
    #     @summary: start TLS protocol
    #     @param sslContext: {ssl.ClientContextFactory | ssl.DefaultOpenSSLContextFactory} context use for TLS protocol
    #     """
    #     self.transport.startTLS(sslContext)
       
    # def startNLA(self, sslContext, callback):
    #     """
    #     @summary: use to start NLA (NTLM over SSL) protocol
    #                 must be called after startTLS function
    #     """
    #     self.transport.startNLA(sslContext, callback)
        
