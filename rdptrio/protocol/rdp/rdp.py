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
Use to manage RDP stack in twisted
"""

# from rdpy.core.error import CallPureVirtualFuntion, InvalidValue
# import rdptrio.protocol.rdp.pdu.layer as PduLayer
# import rdptrio.protocol.rdp.sec as sec
# from rdptrio.protocol.rdp.t125 import mcs
import rdptrio.protocol.rdp.x224 as x224
import rdptrio.protocol.rdp.tpkt as tpkt
import sys
import trio
# import rdptrio.protocol.rdp.pdu.data as PduData
# import rdptrio.protocol.rdp.pdu.caps as PduCaps
# import rdpy.protocol.rdp.pdu as pdu
# import rdpy.core.log as log
import logging
import queue
# import rdptrio.protocol.rdp.tpkt as tpkt, , rdptrio.protocol.rdp.sec as sec
# from rdptrio.protocol.rdp.t125 import mcs, gcc
# from rdptrio.protocol.rdp.nla import cssp, ntlm

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

class SecurityLevel(object):
    """
    @summary: RDP security level
    """
    RDP_LEVEL_RDP = 0
    RDP_LEVEL_SSL = 1
    RDP_LEVEL_NLA = 2
    
class Stream():
    
    def __init__(self):
        self.sendQueue = queue.Queue()
        
    def addPacket(self, packet):
        self.sendQueue.put(packet)

    def getPacket(self):
        if not self.sendQueue.empty():
            return self.sendQueue.get()
        else:
            return False
    
class RDPClientController():
    """
    
    Manage RDP stack as client
    """
    def __init__(self):
        
        logger.debug('[RDPClientController]')
        
        #list of observer
        self._clientObserver = []
        self._sendQueue = Stream()
        #PDU layer
        # self._pduLayer = PduLayer.Client()
        #secure layer
        # self._secLayer = sec.Client()
        #multi channel service
        # self._mcsLayer = mcs.Client()
        
        # #transport pdu layer
        self._x224Layer = x224.Client()
        #transport packet (protocol layer)
        self._tpktLayer = tpkt.TPKT(self._x224Layer)
        #fastpath stack
        # self._pduLayer.initFastPath(self._secLayer)
        # self._secLayer.initFastPath(self._tpktLayer)
        # #is pdu layer is ready to send
        # self._isReady = False
    
    def sendConnect(self):
        packageTPKT = self._tpktLayer.getPacket()
        
        self._sendQueue.addPacket(packageTPKT)
        
    
    async def sendConnectionRequestPDU(self, client_stream):
        logger.debug("sender init")
        packageTPKT = self._tpktLayer.getPacket()
        #SEND
        #XFREERDP = b'\x03\x00\x00\x31\x2c\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x4c\x75\x63\x61\x73\x20\x42\x72\x69\x74\x6f\x0d\x0a\x01\x00\x08\x00\x03\x00\x00\x00'
        #XFREERDP = b'\x16\x03\x01\x01:\x01\x00\x01\x16\x03\x03\x8c\x1b\xfb\xacL\x9epE\xfb\xb8@\x03\xc8-L!% \xe5\x1b-X(\xa8\x12\xda\xd0D\xe2M\xbc\xa7\x9c\xf8x\x82\x01\xe0cfa\xb0L\xcc`\x8a\x16jXN9~}\xd6\xc0\xd2\xbf\x06\\\x12\x96\x99\x98\x81\xbb\xd58E\x00>\x13\x02\x130\x13\x01\xc0,\xc0\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0,\xc0/\x00\x9e\xc0$\xc0(\x00k\xc0#\xc0'\x00g\xc0\n\xc0\x14\x00;C\x00\x9c\xc0\x13\x003\x00\x9d\x00\x9c\x00=\x00<\x003\x00/\x00\xff\x01\x00\x00\xaf\x00\x00\x00\x12\x00\x10\x00\x00\r192.168.0.236\x00\x0b\x00\x04\x03\x00\x01\x02\x00\n\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x02\x00\x01\x01\x03\x01\x04\x00#\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\r\x00*\x00(\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\t\x08\n\x08\x08\x08\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x02\x04\x02\x05\x02\x06\x02\x00+\x00\t\x08\x03\x04\x03\x03\x02\x03\x01\x00-\x00\x02\x01\x01\x00\x0f\x00\x01\x01'
        #XFREERDP = b'\x16\x03\x03\x01\x06\x00\x01\x02\x01\x00g\x92[\x4a\xba\xde:\x80\x00\\\x9c\x94I\xb1\xb4\xd0\xa6*\xcdW\xfcJ\xb3\xfb\x9a\x07\xca6\x04\xcb\xba5\xdb\x18U\xc7\xfa+\xc9\xa3\xf7\x902\x0e\xc1\xb4\xff\xed\xdf\x1a\x87A\x9dGn\x01\xdd+\\\x17\xd9\xb7\xbe\xeb\x03+\xd5\ry,\x88D\x03\x87&i#&2x-rJ\xe5E\xbb\xa1q\xca\x83:\xc3@\x77,\x8b\x08\xa8J.\xf9\xc2\x80\xf5\x02eTr\xb0#\x87\xfb)Ve\x0a\\\x38\xbb\xf2\xe9\x9e\xe9x\x1a \xe9\xa4\x9c\x1a\x0ei\xce\xc8U\xd4\x8d\\\xb79\xac\xa2y\xd6\xa68U\xf1\xf6\xba\xfdN3\xb5D7\xf7K\x8aa\x85\x9b\xf1\xadP\xa03a\xf9\xffT\x0e\x1c\xb0g\xa8\x02\x31\x82/\xd1\xdeEXV\x859\xfa\xef\x91\xd0\x15.&K\xf9\x08\x95\xc1?\xc7UH\x8ew\xd8CQ=\xe2\xad_q\xc2\x8e\x99\xd2&\x1e\xdc\x0c\xd9O\x06\xe2F\x0b\x10\xc5\x97\xed\xe1\x99h\xe9\xff$\x89\xe3\xb4\x9e\x16\xdf\x0f^~WT\xa8\xd0\xb0\xe7S\xd2\x9bE\x89\x8c^\x14\x03\x03\x00\x01\x16\x03\x03\x00(\x8c\x99\xa5\xc2\xbf&\x8aL\x1e\xa9E\x16\xc2-\xfe\xedA%q\x9d=VX6\xee\xb3\xa3\x96\xc1Yn\x15\x96\xe1\x04a\xfaE\xda'

        
        #RECEIVE
        #XFREERDP = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f\x08\x00\x02\x00\x00\x00'
        #XFREERDP = b'\x16\x03\x03\x049\x02\x00\x00Q\x03\x03e\xb7\xf3o\xb8f\xe3\xd6\xe5y\xbc#B\x91j\xe9\xdbK\x97\xc2\xc7\xac\xc5\x98\x36\xedSz\x08b\xfc\xe2\ta \x00\x00\xcc\x90^\xc6k\x12\xe5\xd6\x88\xa1\xd5\x1cno\x99\xcf\x94\x10\xad\x86\xbf>Jg\x8a\t&>\xa9\x9c\xfc*\xb3\x8b\x0b9% \xa4\xaa\x1c9[\xd1\x9b\x8f\xa4\xb0\t\xd0\x00\x00\x09\x00\x17\x00\x00\xff\x01\x00\x01\x00\x0b\x00\x02\xec\x00\x02\xe9\x00\x02\xe60\x82\x02\xe230\x82\x01\xca\xa0\x03\x02\x01\x02\x02\x10\x18\x12\x395K\xcb\x84\x81C\x14\xea\x84Gs2\xe60\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000\x1a1\x18\x16\x06\x03U\x04\x031\x0fDESKTOP-6A16BD10\x1e\x17\x0d\x230\x12\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\t\x08\n\x08\x08\x08\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x03\x03\x03\x02\x04\x02\x05\x02\x06\x02\x00+\x00\t\x08\x03\x04\x03\x03\x02\x03\x01\x00-\x00\x02\x01\x01\x00\x0f\x00\x01\x01'
        #XFREERDP = b'\x14\x03\x03\x00\x01\x01\x16\x03\x03\x00(\x00\x00\x00\x00\x00\x00\x00\xb8d\x1d\xbb\x1aV\xe1F\x97\xcf\x159~\x8a\x16#\x84\xbbx\x19%?\t\x1d\x0c\xe7\x87+\x03\xa5\x0b\x9b'

        

        #                          TPKT
        #         |version |reserved| sizeheaderTPKT  |sizeX224| CR/CDT |     DST/REF     |     SRC-REF     |classopt|
        #         |------- |--------|-----------------|--------|--------|-----------------|-----------------|--------|
        #MEU    -> 00000011|00000000|00000000 00001000|00000101|11100000|00000000 00000000|00000000 00000000|00000000|
        #          00000011 00000000 00000000 00001000 00000101 11100000 00000000 00000000 00000000 00000000

        #RDP BIN-> 00000011 00000000 00000000 00110001 00101100 11100000 00000000 00000000 00000000 00000000 00000000 01000011 01101111 01101111 01101011 01101001 01100101 00111010 00100000 01101101 01110011 01110100 01110011 01101000 01100001 01110011 01101000 00111101 01001100 01110101 01100011 01100001 01110011 00100000 01000010 01110010 01101001 01110100 01101111 00001101 00001010 00000001 00000000 00001000 00000000 00000011 00000000 00000000
        #          00000011 00000000 00000000 00010011 00001110 11010000 00000000 00000000 00010010 00110100 00000000 00000010 00011111 00001000 00000000 00000010 00000000 00000000 00000000
        #RDP HEX-> 030000312ce00000000000436f6f6b69653a206d737473686173683d4c7563617320427269746f0d0a0100080003000000
        #RED HEX-> b'\x03\x00\x001,\xe0\x00\x00\x00\x00\x00Cookie: mstshash=Lucas Brito\r\n\x01\x00\x08\x00\x03\x00\x00\x00'
        #RDP OUTRO -> 030000130ed00000123400021f080002000000
        
        
    # def getProtocol(self):
    #     """
    #     @return: return Protocol layer for twisted
    #     In case of RDP TPKT is the Raw layer
    #     """
        
    #     return cssp.CSSP(self._tpktLayer, ntlm.NTLMv2(self._secLayer._info.domain.value, self._secLayer._info.userName.value, self._secLayer._info.password.value))
      
    # def setPerformanceSession(self):
    #     """
    #     @summary: Set particular flag in RDP stack to avoid wall-paper, theme, menu animation etc...
    #     """
    #     self._secLayer._info.extendedInfo.performanceFlags.value = sec.PerfFlag.PERF_DISABLE_WALLPAPER | sec.PerfFlag.PERF_DISABLE_MENUANIMATIONS | sec.PerfFlag.PERF_DISABLE_CURSOR_SHADOW | sec.PerfFlag.PERF_DISABLE_THEMING | sec.PerfFlag.PERF_DISABLE_FULLWINDOWDRAG
               
    # def setUsername(self, username):
    #     """
    #     @summary: Set the username for session
    #     @param username: {string} username of session
    #     """
    #     #username in PDU info packet
    #     self._secLayer._info.userName.value = username
    #     self._secLayer._licenceManager._username = username
        
    # def setPassword(self, password):
    #     """
    #     @summary: Set password for session
    #     @param password: {string} password of session
    #     """
    #     self.setAutologon()
    #     self._secLayer._info.password.value = password
        
    # def setDomain(self, domain):
    #     """
    #     @summary: Set the windows domain of session
    #     @param domain: {string} domain of session
    #     """
    #     self._secLayer._info.domain.value = domain
        
    # def setAutologon(self):
    #     """
    #     @summary: enable autologon
    #     """
    #     self._secLayer._info.flag |= sec.InfoFlag.INFO_AUTOLOGON
              
    # def setKeyboardLayout(self, layout):
    #     """
    #     @summary: keyboard layout
    #     @param layout: us | fr
    #     """
    #     if layout == "fr":
    #         self._mcsLayer._clientSettings.CS_CORE.kbdLayout.value = gcc.KeyboardLayout.FRENCH
    #     elif layout == "us":
    #         self._mcsLayer._clientSettings.CS_CORE.kbdLayout.value = gcc.KeyboardLayout.US
    
    # def setHostname(self, hostname):
    #     """
    #     @summary: set hostname of machine
    #     """
    #     self._mcsLayer._clientSettings.CS_CORE.clientName.value = hostname[:15] + "\x00" * (15 - len(hostname))
    #     self._secLayer._licenceManager._hostname = hostname
        
    # def setSecurityLevel(self, level):
    #     """
    #     @summary: Request basic security
    #     @param level: {SecurityLevel}
    #     """
    #     if level == SecurityLevel.RDP_LEVEL_RDP:
    #         self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_RDP
    #     elif level == SecurityLevel.RDP_LEVEL_SSL:
    #         self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_SSL
    #     elif level == SecurityLevel.RDP_LEVEL_NLA:
    #         self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_SSL | x224.Protocols.PROTOCOL_HYBRID
