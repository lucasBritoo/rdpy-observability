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
import rdptrio.protocol.rdp.pdu.layer as PduLayer
import rdptrio.protocol.rdp.pdu.data as PduData
import rdptrio.protocol.rdp.pdu.caps as PduCaps
# import rdpy.protocol.rdp.pdu as pdu
# import rdpy.core.log as log
import logging
import rdptrio.protocol.rdp.tpkt as tpkt, rdptrio.protocol.rdp.x224 as x224, rdptrio.protocol.rdp.sec as sec
from rdptrio.protocol.rdp.t125 import mcs, gcc
from rdptrio.protocol.rdp.nla import cssp, ntlm

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class SecurityLevel(object):
    """
    @summary: RDP security level
    """
    RDP_LEVEL_RDP = 0
    RDP_LEVEL_SSL = 1
    RDP_LEVEL_NLA = 2

class RDPClientController():
    """
    
    Manage RDP stack as client
    """
    def __init__(self):
        
        logger.debug('[RDPClientController]')
        
        #list of observer
        self._clientObserver = []
        #PDU layer
        self._pduLayer = PduLayer.Client(self)
        #secure layer
        
        self._secLayer = sec.Client(self._pduLayer)
        #multi channel service
        self._mcsLayer = mcs.Client(self._secLayer)
        #transport pdu layer
        self._x224Layer = x224.Client(self._mcsLayer)
        #transport packet (protocol layer)
        self._tpktLayer = tpkt.TPKT(self._x224Layer)
        #fastpath stack
        self._pduLayer.initFastPath(self._secLayer)
        self._secLayer.initFastPath(self._tpktLayer)
        #is pdu layer is ready to send
        self._isReady = False
        
    def getProtocol(self):
        """
        @return: return Protocol layer for twisted
        In case of RDP TPKT is the Raw layer
        """
        
        return cssp.CSSP(self._tpktLayer, ntlm.NTLMv2(self._secLayer._info.domain.value, self._secLayer._info.userName.value, self._secLayer._info.password.value))
    
    def getColorDepth(self):
        """
        @return: color depth set by the server (15, 16, 24)
        """
        return self._pduLayer._serverCapabilities[PduCaps.CapsType.CAPSTYPE_BITMAP].capability.preferredBitsPerPixel.value
    
    def getKeyEventUniCodeSupport(self):
        """
        @return: True if server support unicode input
        """
        return self._pduLayer._serverCapabilities[PduCaps.CapsType.CAPSTYPE_INPUT].capability.inputFlags.value & PduCaps.InputFlags.INPUT_FLAG_UNICODE
        
    def setPerformanceSession(self):
        """
        @summary: Set particular flag in RDP stack to avoid wall-paper, theme, menu animation etc...
        """
        self._secLayer._info.extendedInfo.performanceFlags.value = sec.PerfFlag.PERF_DISABLE_WALLPAPER | sec.PerfFlag.PERF_DISABLE_MENUANIMATIONS | sec.PerfFlag.PERF_DISABLE_CURSOR_SHADOW | sec.PerfFlag.PERF_DISABLE_THEMING | sec.PerfFlag.PERF_DISABLE_FULLWINDOWDRAG
        
    def setScreen(self, width, height):
        """
        @summary: Set screen dim of session
        @param width: width in pixel of screen
        @param height: height in pixel of screen
        """
        #set screen definition in MCS layer
        self._mcsLayer._clientSettings.getBlock(gcc.MessageType.CS_CORE).desktopHeight.value = height
        self._mcsLayer._clientSettings.getBlock(gcc.MessageType.CS_CORE).desktopWidth.value = width
        
    def setUsername(self, username):
        """
        @summary: Set the username for session
        @param username: {string} username of session
        """
        #username in PDU info packet
        self._secLayer._info.userName.value = username
        self._secLayer._licenceManager._username = username
        
    def setPassword(self, password):
        """
        @summary: Set password for session
        @param password: {string} password of session
        """
        self.setAutologon()
        self._secLayer._info.password.value = password
        
    def setDomain(self, domain):
        """
        @summary: Set the windows domain of session
        @param domain: {string} domain of session
        """
        self._secLayer._info.domain.value = domain
        
    def setAutologon(self):
        """
        @summary: enable autologon
        """
        self._secLayer._info.flag |= sec.InfoFlag.INFO_AUTOLOGON
        
    def setAlternateShell(self, appName):
        """
        @summary: set application name of app which start at the begining of session
        @param appName: {string} application name
        """
        self._secLayer._info.alternateShell.value = appName
        
    def setKeyboardLayout(self, layout):
        """
        @summary: keyboard layout
        @param layout: us | fr
        """
        if layout == "fr":
            self._mcsLayer._clientSettings.CS_CORE.kbdLayout.value = gcc.KeyboardLayout.FRENCH
        elif layout == "us":
            self._mcsLayer._clientSettings.CS_CORE.kbdLayout.value = gcc.KeyboardLayout.US
    
    def setHostname(self, hostname):
        """
        @summary: set hostname of machine
        """
        self._mcsLayer._clientSettings.CS_CORE.clientName.value = hostname[:15] + "\x00" * (15 - len(hostname))
        self._secLayer._licenceManager._hostname = hostname
        
    def setSecurityLevel(self, level):
        """
        @summary: Request basic security
        @param level: {SecurityLevel}
        """
        if level == SecurityLevel.RDP_LEVEL_RDP:
            self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_RDP
        elif level == SecurityLevel.RDP_LEVEL_SSL:
            self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_SSL
        elif level == SecurityLevel.RDP_LEVEL_NLA:
            self._x224Layer._requestedProtocol = x224.Protocols.PROTOCOL_SSL | x224.Protocols.PROTOCOL_HYBRID
        
    def addClientObserver(self, observer):
        """
        @summary: Add observer to RDP protocol
        @param observer: new observer to add
        """
        self._clientObserver.append(observer)
        
    def removeClientObserver(self, observer):
        """
        @summary: Remove observer to RDP protocol stack
        @param observer: observer to remove
        """
        for i in range(0, len(self._clientObserver)):
            if self._clientObserver[i] == observer:
                del self._clientObserver[i]
                return
        
    def onUpdate(self, rectangles):
        """
        @summary: Call when a bitmap data is received from update PDU
        @param rectangles: [pdu.BitmapData] struct
        """
        for observer in self._clientObserver:
            #for each rectangle in update PDU
            for rectangle in rectangles:
                observer.onUpdate(rectangle.destLeft.value, rectangle.destTop.value, rectangle.destRight.value, rectangle.destBottom.value, rectangle.width.value, rectangle.height.value, rectangle.bitsPerPixel.value, rectangle.flags.value & PduData.BitmapFlag.BITMAP_COMPRESSION, rectangle.bitmapDataStream.value)
                
    def onReady(self):
        """
        @summary: Call when PDU layer is connected
        """
        self._isReady = True
        #signal all listener
        for observer in self._clientObserver:
            observer.onReady()
            
    def onSessionReady(self):
        """
        @summary: Call when Windows session is ready (connected)
        """
        self._isReady = True
        #signal all listener
        for observer in self._clientObserver:
            observer.onSessionReady()
            
    def onClose(self):
        """
        @summary: Event call when RDP stack is closed
        """
        self._isReady = False
        for observer in self._clientObserver:
            observer.onClose()
    
    def sendPointerEvent(self, x, y, button, isPressed):
        """
        @summary: send pointer events
        @param x: x position of pointer
        @param y: y position of pointer
        @param button: 1 or 2 or 3
        @param isPressed: true if button is pressed or false if it's released
        """
        if not self._isReady:
            return

        try:
            if button == 4 or button == 5:
                event = PduData.PointerExEvent()
                if isPressed:
                    event.pointerFlags.value |= PduData.PointerExFlag.PTRXFLAGS_DOWN

                if button == 4:
                    event.pointerFlags.value |= PduData.PointerExFlag.PTRXFLAGS_BUTTON1
                elif button == 5:
                    event.pointerFlags.value |= PduData.PointerExFlag.PTRXFLAGS_BUTTON2

            else:
                event = PduData.PointerEvent()
                if isPressed:
                    event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_DOWN
                
                if button == 1:
                    event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_BUTTON1
                elif button == 2:
                    event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_BUTTON2
                elif button == 3:
                    event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_BUTTON3
                else:
                    event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_MOVE
            
            # position
            event.xPos.value = x
            event.yPos.value = y
            
            # send proper event
            self._pduLayer.sendInputEvents([event])
          
        except:  
        # except InvalidValue:
            logging.info("try send pointer event with incorrect position")
    
    def sendWheelEvent(self, x, y, step, isNegative = False, isHorizontal = False):
        """
        @summary: Send a mouse wheel event
        @param x: x position of pointer
        @param y: y position of pointer
        @param step: number of step rolled
        @param isHorizontal: horizontal wheel (default is vertical)
        @param isNegative: is upper (default down)
        """
        if not self._isReady:
            return

        try:
            event = PduData.PointerEvent()
            if isHorizontal:
                event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_HWHEEL
            else:
                event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_WHEEL
                
            if isNegative:
                event.pointerFlags.value |= PduData.PointerFlag.PTRFLAGS_WHEEL_NEGATIVE
                
            event.pointerFlags.value |= (step & PduData.PointerFlag.WheelRotationMask)
            
            #position
            event.xPos.value = x
            event.yPos.value = y
            
            #send proper event
            self._pduLayer.sendInputEvents([event])
            
        except:
        # except InvalidValue:
            logging.info("try send wheel event with incorrect position")
            
    def sendKeyEventScancode(self, code, isPressed, extended = False):
        """
        @summary: Send a scan code to RDP stack
        @param code: scan code
        @param isPressed: True if key is pressed and false if it's released
        @param extended: {boolean} extended scancode like ctr or win button
        """
        if not self._isReady:
            return
        
        try:
            event = PduData.ScancodeKeyEvent()
            event.keyCode.value = code
            if not isPressed:
                event.keyboardFlags.value |= PduData.KeyboardFlag.KBDFLAGS_RELEASE
            
            if extended:
                event.keyboardFlags.value |= PduData.KeyboardFlag.KBDFLAGS_EXTENDED
                
            #send event
            self._pduLayer.sendInputEvents([event])
            
        except:
        # except InvalidValue:
            logging.info("try send bad key event")
            
    def sendKeyEventUnicode(self, code, isPressed):
        """
        @summary: Send a scan code to RDP stack
        @param code: unicode
        @param isPressed: True if key is pressed and false if it's released
        """
        if not self._isReady:
            return
        
        try:
            event = PduData.UnicodeKeyEvent()
            event.unicode.value = code
            if not isPressed:
                event.keyboardFlags.value |= PduData.KeyboardFlag.KBDFLAGS_RELEASE
            
            #send event
            self._pduLayer.sendInputEvents([event])
            
        except:
        
        # except InvalidValue:
            logging.info("try send bad key event")
            
    def sendRefreshOrder(self, left, top, right, bottom):
        """
        @summary: Force server to resend a particular zone
        @param left: left coordinate
        @param top: top coordinate
        @param right: right coordinate
        @param bottom: bottom coordinate
        """
        refreshPDU = PduData.RefreshRectPDU()
        rect = PduData.InclusiveRectangle()
        rect.left.value = left
        rect.top.value = top
        rect.right.value = right
        rect.bottom.value = bottom
        refreshPDU.areasToRefresh._array.append(rect)
        self._pduLayer.sendDataPDU(refreshPDU)
            
    def close(self):
        """
        @summary: Close protocol stack
        """
        self._pduLayer.close()
