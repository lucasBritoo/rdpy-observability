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
# from rdpy.core.error import InvalidExpectedDataException
# import rdpy.core.log as log
import logging
from rdptrio.core.type import CallableValue, String, UInt8, UInt16Le, UInt32Le, sizeof, ArrayType
from rdptrio.core.config import Config

logger = logging.getLogger(__name__)
config = Config('rdptrio/config/gcc.yaml')


"""
Definition of structure use for capabilities nego
Use in PDU layer
"""

class CacheEntry():#CompositeType):
    """
    @summary: Use in capability cache exchange
    @see: http://msdn.microsoft.com/en-us/library/cc240566.aspx
    """
    def __init__(self):
        #CompositeType.__init__(self)
        self.cacheEntries = UInt16Le()
        self.cacheMaximumCellSize = UInt16Le()
    
class Capability():#CompositeType):
    """
    @summary: A capability
    @see: http://msdn.microsoft.com/en-us/library/cc240486.aspx
    """
    def __init__(self, capability = None):
        #CompositeType.__init__(self)
        self.capabilitySetType = UInt16Le(lambda:capability.__class__._TYPE_)
        self.lengthCapability = UInt16Le(lambda:sizeof(self))
                
        if capability is None:
            raise ValueError("unknown Capability")
        elif not "_TYPE_" in capability.__class__.__dict__:
            raise ValueError("Try to send an invalid capability")
            
        self.capability = capability

class GeneralCapability():#CompositeType):
    """
    @summary: General capability (protocol version and compression mode)
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240549.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_GENERAL")
    
    def __init__(self, readLen = None):
        # CompositeType.__init__(self, readLen = readLen)
        self.osMajorType = UInt16Le()
        self.osMinorType = UInt16Le()
        self.protocolVersion = UInt16Le(0x0200, constant = True)
        self.pad2octetsA = UInt16Le()
        self.generalCompressionTypes = UInt16Le(0, constant = True)
        self.extraFlags = UInt16Le()
        self.updateCapabilityFlag = UInt16Le(0, constant = True)
        self.remoteUnshareFlag = UInt16Le(0, constant = True)
        self.generalCompressionLevel = UInt16Le(0, constant = True)
        self.refreshRectSupport = UInt8()
        self.suppressOutputSupport = UInt8()
        
class BitmapCapability():#CompositeType):
    """
    @summary: Bitmap format Capability
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240554.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_BITMAP")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.preferredBitsPerPixel = UInt16Le()
        self.receive1BitPerPixel = UInt16Le(0x0001)
        self.receive4BitsPerPixel = UInt16Le(0x0001)
        self.receive8BitsPerPixel = UInt16Le(0x0001)
        self.desktopWidth = UInt16Le()
        self.desktopHeight = UInt16Le()
        self.pad2octets = UInt16Le()
        self.desktopResizeFlag = UInt16Le()
        self.bitmapCompressionFlag = UInt16Le(0x0001, constant = True)
        self.highColorFlags = UInt8(0)
        self.drawingFlags = UInt8()
        self.multipleRectangleSupport = UInt16Le(0x0001, constant = True)
        self.pad2octetsB = UInt16Le()
        
class OrderCapability():#CompositeType):
    """
    @summary: Order capability list all drawing order supported
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240556.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_ORDER")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.terminalDescriptor = String("\x00" * 16, readLen = CallableValue(16))
        self.pad4octetsA = UInt32Le(0)
        self.desktopSaveXGranularity = UInt16Le(1)
        self.desktopSaveYGranularity = UInt16Le(20)
        self.pad2octetsA = UInt16Le(0)
        self.maximumOrderLevel = UInt16Le(1)
        self.numberFonts = UInt16Le()
        self.orderFlags = UInt16Le(config.get_value("orderFlag", "NEGOTIATEORDERSUPPORT"))
        self.orderSupport = ArrayType(UInt8, init = [UInt8(0) for _ in range (0, 32)],  readLen = CallableValue(32))
        self.textFlags = UInt16Le()
        self.orderSupportExFlags = UInt16Le()
        self.pad4octetsB = UInt32Le()
        self.desktopSaveSize = UInt32Le(480 * 480)
        self.pad2octetsC = UInt16Le()
        self.pad2octetsD = UInt16Le()
        self.textANSICodePage = UInt16Le(0)
        self.pad2octetsE = UInt16Le()
        
class BitmapCacheCapability():#CompositeType):
    """
    @summary: Order use to cache bitmap very useful
    client -> server
    @see: http://msdn.microsoft.com/en-us/library/cc240559.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_BITMAPCACHE")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.pad1 = UInt32Le()
        self.pad2 = UInt32Le()
        self.pad3 = UInt32Le()
        self.pad4 = UInt32Le()
        self.pad5 = UInt32Le()
        self.pad6 = UInt32Le()
        self.cache0Entries = UInt16Le()
        self.cache0MaximumCellSize = UInt16Le()
        self.cache1Entries = UInt16Le()
        self.cache1MaximumCellSize = UInt16Le()
        self.cache2Entries = UInt16Le()
        self.cache2MaximumCellSize = UInt16Le()
        
class PointerCapability():#CompositeType):
    """
    @summary: Use to indicate pointer handle of client
    Paint by server or per client
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240562.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_POINTER")
    
    def __init__(self, isServer = False, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.colorPointerFlag = UInt16Le()
        self.colorPointerCacheSize = UInt16Le(20)
        #old version of rdp doesn't support ...
        self.pointerCacheSize = UInt16Le(conditional = lambda:isServer)
        
class InputCapability():#CompositeType):
    """
    @summary: Use to indicate input capabilities
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240563.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_INPUT")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.inputFlags = UInt16Le()
        self.pad2octetsA = UInt16Le()
        #same value as gcc.ClientCoreSettings.kbdLayout
        self.keyboardLayout = UInt32Le()
        #same value as gcc.ClientCoreSettings.keyboardType
        self.keyboardType = UInt32Le()
        #same value as gcc.ClientCoreSettings.keyboardSubType
        self.keyboardSubType = UInt32Le()
        #same value as gcc.ClientCoreSettings.keyboardFnKeys
        self.keyboardFunctionKey = UInt32Le()
        #same value as gcc.ClientCoreSettingrrs.imeFileName
        self.imeFileName = String("\x00" * 64, readLen = CallableValue(64))
        
class BrushCapability():#CompositeType):
    """
    @summary: Use to indicate brush capability
    client -> server
    @see: http://msdn.microsoft.com/en-us/library/cc240564.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_BRUSH")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.brushSupportLevel = UInt32Le(config.get_value("brushSupport", "BRUSH_DEFAULT"))
        
class GlyphCapability():#CompositeType):
    """
    @summary: Use in font order
    client -> server
    @see: http://msdn.microsoft.com/en-us/library/cc240565.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_GLYPHCACHE")
    
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.glyphCache = ArrayType(CacheEntry, init = [CacheEntry() for _ in range(0,10)], readLen = CallableValue(10))
        self.fragCache = UInt32Le()
        #all fonts are sent with bitmap format (very expensive)
        self.glyphSupportLevel = UInt16Le(config.get_value("glyphSupport", "GLYPH_SUPPORT_NONE"))
        self.pad2octets = UInt16Le()
        
class OffscreenBitmapCacheCapability():#CompositeType):
    """
    @summary: use to cached bitmap in offscreen area
    client -> server
    @see: http://msdn.microsoft.com/en-us/library/cc240550.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_OFFSCREENCACHE")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.offscreenSupportLevel = UInt32Le(config.get_value("offScreenSupport", "VALUE_FALSE"))
        self.offscreenCacheSize = UInt16Le()
        self.offscreenCacheEntries = UInt16Le()
        
class VirtualChannelCapability():#CompositeType):
    """
    @summary: use to determine virtual channel compression
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240551.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_VIRTUALCHANNEL")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.flags = UInt32Le(config.get_value("virtualChannelCompression", "VCCAPS_NO_COMPR"))
        self.VCChunkSize = UInt32Le(optional = True)
        
class SoundCapability():#CompositeType):
    """
    @summary: Use to exchange sound capability
    client -> server
    @see: http://msdn.microsoft.com/en-us/library/cc240552.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_SOUND")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.soundFlags = UInt16Le(config.get_value("soundCapability", "NONE"))
        self.pad2octetsA = UInt16Le()
        
class ControlCapability():#CompositeType):
    """
    @summary: client -> server but server ignore contents! Thanks krosoft for brandwidth
    @see: http://msdn.microsoft.com/en-us/library/cc240568.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_CONTROL")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.controlFlags = UInt16Le()
        self.remoteDetachFlag = UInt16Le()
        self.controlInterest = UInt16Le(0x0002)
        self.detachInterest = UInt16Le(0x0002)
    
class WindowActivationCapability():#CompositeType):
    """
    @summary: client -> server but server ignore contents! Thanks krosoft for brandwidth
    @see: http://msdn.microsoft.com/en-us/library/cc240569.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_ACTIVATION")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.helpKeyFlag = UInt16Le()
        self.helpKeyIndexFlag = UInt16Le()
        self.helpExtendedKeyFlag = UInt16Le()
        self.windowManagerKeyFlag = UInt16Le()
        
class FontCapability():#CompositeType):
    """
    @summary: Use to indicate font support
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240571.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_FONT")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.fontSupportFlags = UInt16Le(0x0001)
        self.pad2octets = UInt16Le()
        
class ColorCacheCapability():#CompositeType):
    """
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc241564.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_COLORCACHE")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.colorTableCacheSize = UInt16Le(0x0006)
        self.pad2octets = UInt16Le()
        
class ShareCapability():#CompositeType):
    """
    @summary: Use to advertise channel id of server
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240570.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSTYPE_SHARE")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.nodeId = UInt16Le()
        self.pad2octets = UInt16Le()
        
class MultiFragmentUpdate():#CompositeType):
    """
    @summary: Use to advertise fast path max buffer to use
    client -> server
    server -> client
    @see: http://msdn.microsoft.com/en-us/library/cc240649.aspx
    """
    _TYPE_ = config.get_value("capsType", "CAPSETTYPE_MULTIFRAGMENTUPDATE")
    
    def __init__(self, readLen = None):
        #CompositeType.__init__(self, readLen = readLen)
        self.MaxRequestSize = UInt32Le(0)