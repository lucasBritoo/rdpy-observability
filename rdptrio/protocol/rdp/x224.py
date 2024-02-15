from rdptrio.core.type import UInt8, UInt16Le, UInt32Le, String
from rdptrio.core.config import Config
import logging
import struct


logger = logging.getLogger(__name__)
config = Config('rdptrio/config/gcc.yaml')

class Protocols():
    #@summary: Protocols available for x224 layer
    #@see: https://msdn.microsoft.com/en-us/library/cc240500.aspx
    def __init__(self):
        self.PROTOCOL_RDP= 0x00000000
        self.PROTOCOL_SSL= 0x00000001
        self.PROTOCOL_HYBRID= 0x00000002
        self.PROTOCOL_CERT_NOT_ON_SERVER= 0x00000003
        self.PROTOCOL_HYBRID_EX= 0x00000008

class MessageTypeX224():
    
    def __init__(self):
        self.X224_TPDU_CONNECTION_REQUEST= 0xE0
        self.X224_TPDU_DESTINATION_REFERENCE= 0x00
        self.X224_TPDU_SOURCE_REFERENCE= 0x00
        self.X224_TPDU_CLASS_OPTION= 0x00
        self.X224_TPDU_CONNECTION_CONFIRM= 0xD0
        self.X224_TPDU_DISCONNECT_REQUEST= 0x80
        self.X224_TPDU_DATA= 0xF0
        self.X224_TPDU_ERROR= 0x70

class NegotiationX224():
    #https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
    def __init__(self):
        self.TYPE_RDP_NEG_REQ= 0x01
        self.TYPE_RDP_NEG_RSP= 0x02
        self.TYPE_RDP_NEG_FAILURE= 0x03
        self.FLAG_RESTRICTED_ADMIN_MODE_REQUIRED = 0x01
        self.FLAG_REDIRECTED_AUTHENTICATION_MODE_REQUIRED = 0x02
        self.FLAG_CORRELATION_INFO_PRESENT = 0x08
        self.FLAG_NO_FLAGS = 0x00
        self.LENGHT = 0x08
     
class X224Layer():#LayerAutomata, IStreamSender):
    """
    @summary:  x224 layer management
                there is an connection automata
    """
    def __init__(self):
        logger.debug('[X224Layer]')
        self._requestedProtocol = Protocols().PROTOCOL_SSL | Protocols().PROTOCOL_HYBRID
        self.connectionRequest = UInt8(MessageTypeX224().X224_TPDU_CONNECTION_REQUEST, "connectionRequest")
        self.destinationReference = UInt16Le(MessageTypeX224().X224_TPDU_DESTINATION_REFERENCE, "destinationReference")
        self.sourceReference = UInt16Le(MessageTypeX224().X224_TPDU_SOURCE_REFERENCE, "sourceReference")
        self.classOption = UInt8(MessageTypeX224().X224_TPDU_CLASS_OPTION, "classOption")
        self.cookie = String("Cookie: mstshash=eltons", "cookie")
        self.cookieTerminator = String("\r\n", "cookieTerminator")
        self.negotiation = UInt8(NegotiationX224().TYPE_RDP_NEG_REQ, "negotitionType")
        self.flags = UInt8(NegotiationX224().FLAG_NO_FLAGS, "negotiationFlags")
        self.length = UInt16Le(NegotiationX224().LENGHT, "lenght")
        self.protocol = UInt32Le(Protocols().PROTOCOL_SSL, "protocol")
        
    
    def getHeader(self):
        return [self.connectionRequest, self.destinationReference, self.sourceReference, 
                self.classOption, self.cookie, self.cookieTerminator, self.negotiation, self.flags, self.length, self.protocol]
    
    def getHeaderSize(self):
        
        _size = 0
        for attribute in self.getHeader():
            _size += attribute._size
        
        return UInt8(_size, "sizeX224")
        
    def getPacket(self):
        return [self.getHeaderSize, self.getHeader() ]
    
    def getPacketSize(self):
        
        _headerSize = self.getHeaderSize()
        _packetSize = struct.unpack(_headerSize._structFormat, _headerSize._value)[0]
  
        return (_headerSize._size + _packetSize)
    
    @property
    def _size(self):
        return self.getPacketSize()
    
    @property
    def _value(self):
        
        value = [self.getHeaderSize()]
        
        for frame in self.getHeader():
            value.append(frame)
        return value
  
    
    # def recvData(self, data):
    #     """
    #     @summary: Read data header from packet
    #                And pass to presentation layer
    #     @param data: Stream
    #     """
    #     header = X224DataHeader()
    #     data.readType(header)
    #     self._presentation.recv(data)
        
    # def send(self, message):
    #     """
    #     @summary: Write message packet for TPDU layer
    #                Add TPDU header
    #     @param message: network.Type message
    #     """
    #     self._transport.send((X224DataHeader(), message))
        
class Client(X224Layer):
    """
    @summary: Client automata of TPDU layer
    """
    def __init__(self):
        """
        @param presentation: upper layer, MCS layer in RDP case
        """
        logger.debug('[X224Client]')
        X224Layer.__init__(self)
        
    def connect(self):
        """
        @summary: Connection request for client send a connection request packet
        """
        logger.debug(f"Connect X224Client")
        return self.getPacket()
        # self.sendConnectionRequest()
    
    # def getHeader(self):
    #     connectionRequest = UInt8(config.get_value("messageTypeX224", "X224_TPDU_CONNECTION_REQUEST"))
    #     destinationReference = UInt16Le(config.get_value("messageTypeX224", "X224_TPDU_DESTINATION_REFERENCE"))
    #     sourceReference = UInt8(config.get_value("messageTypeX224", "X224_TPDU_SOURCE_REFERENCE"))
    #     classOption = UInt8(config.get_value("messageTypeX224", "X224_TPDU_CLASS_OPTION"))
        
    #     # _fixedPartFormat =  f"{connectionRequest._structFormat}{destinationReference._structFormat}{sourceReference._structFormat}{classOption._structFormat}"
    #     _fixedPartFormat =  f"B<HBB"
        
    #     fixedPart = struct.pack(
    #        _fixedPartFormat,
    #         connectionRequest._value,
    #         destinationReference._value,
    #         sourceReference._value,
    #         classOption._value
    #     )
        
    #     indicatorField = UInt8_new(len(fixedPart))
    #     _headerFormat = f"{indicatorField._structFormat}{_fixedPartFormat}"
        
    #     packed_data = struct.pack(
    #         _headerFormat,
    #         indicatorField._value,
    #         fixedPart
    #     )
        
    #     return _headerFormat, packed_data
        
        
    # def sendConnectionRequest(self):
    #     """
    #     @summary:  Write connection request message
    #                 Next state is recvConnectionConfirm
    #     @see: http://msdn.microsoft.com/en-us/library/cc240500.aspx
    #     """
    #     logger.debug("[X224Client/SendConnectionRequest]")
    #     message = ClientConnectionRequestPDU()
    #     message.protocolNeg.code.value = config.get_value("negotiationType", "TYPE_RDP_NEG_REQ")
    #     message.protocolNeg.selectedProtocol.value = self._requestedProtocol
    #     print("aqui")
    #     # self._transport.send(message)
    #     # self.setNextState(self.recvConnectionConfirm)
        
    # def recvConnectionConfirm(self, data):
    #     """
    #     @summary:  Receive connection confirm message
    #                 Next state is recvData 
    #                 Call connect on presentation layer if all is good
    #     @param data: Stream that contain connection confirm
    #     @see: response -> http://msdn.microsoft.com/en-us/library/cc240506.aspx
    #     @see: failure ->http://msdn.microsoft.com/en-us/library/cc240507.aspx
    #     """
    #     message = ServerConnectionConfirm()
    #     data.readType(message)
        
    #     if message.protocolNeg.failureCode._is_readed:
    #         raise ValueError("negotiation failure code %x"%message.protocolNeg.failureCode.value)
        
    #     #check presence of negotiation response
    #     if message.protocolNeg._is_readed:
    #         self._selectedProtocol = message.protocolNeg.selectedProtocol.value
    #     else:
    #         self._selectedProtocol = Protocols.PROTOCOL_RDP
        
    #     #NLA protocol doesn't support in actual version of RDPY
    #     if self._selectedProtocol in [ Protocols.PROTOCOL_HYBRID_EX ]:
    #         raise ValueError("RDPY doesn't support PROTOCOL_HYBRID_EX security Layer")
        
    #     #now i'm ready to receive data
    #     self.setNextState(self.recvData)
        
    #     if self._selectedProtocol ==  Protocols.PROTOCOL_RDP:
    #         logger.warning("*" * 43)
    #         logger.warning("*" + " " * 10  + "RDP Security selected" + " " * 10 + "*")
    #         logger.warning("*" * 43)
    #         #connection is done send to presentation
    #         self._presentation.connect()
            
    #     elif self._selectedProtocol ==  Protocols.PROTOCOL_SSL:
    #         logger.info("*" * 43)
    #         logger.info("*" + " " * 10  + "SSL Security selected" + " " * 10 + "*")
    #         logger.info("*" * 43)
    #         self._transport.startTLS(ClientTLSContext())
    #         #connection is done send to presentation
    #         self._presentation.connect()
    
    #     elif self._selectedProtocol == Protocols.PROTOCOL_HYBRID:
    #         logger.info("*" * 43)
    #         logger.info("*" + " " * 10  + "NLA Security selected" + " " * 10 + "*")
    #         logger.info("*" * 43)
    #         self._transport.startNLA(ClientTLSContext(), lambda:self._presentation.connect())

# class ClientConnectionRequestPDU():#CompositeType):
#     """
#     @summary:  Connection request
#                 client -> server
#     @see: http://msdn.microsoft.com/en-us/library/cc240470.aspx
#     """
#     def __init__(self):
#         logger.debug("[X224ClientConnectionRequestPDU]")
#         #CompositeType.__init__(self)
#         self.len = UInt8(lambda:sizeof(self) - 1)
#         self.code = UInt8(config.get_value("messageTypeX224", "X224_TPDU_CONNECTION_REQUEST"), constant = True)
#         self.padding = (UInt16Be(), UInt16Be(), UInt8())
#         self.cookie = String(until = "\x0d\x0a", conditional = lambda:(self.len._is_readed and self.len.value > 14))
#         #read if there is enough data
#         self.protocolNeg = Negotiation(optional = True)

# class Negotiation():#CompositeType):
#     """
#     @summary: Negociate request message
#     @see: request -> http://msdn.microsoft.com/en-us/library/cc240500.aspx
#     @see: response -> http://msdn.microsoft.com/en-us/library/cc240506.aspx
#     @see: failure ->http://msdn.microsoft.com/en-us/library/cc240507.aspx
#     """
#     def __init__(self, optional = False):
#         #CompositeType.__init__(self, optional = optional)
#         self.code = UInt8()
#         self.flag = UInt8(0)
#         #always 8
#         self.len = UInt16Le(0x0008, constant = True)
#         self.selectedProtocol = UInt32Le(conditional = lambda: (self.code.value != config.get_value("negotiationType", "TYPE_RDP_NEG_FAILURE")))
#         self.failureCode = UInt32Le(conditional = lambda: (self.code.value ==config.get_value("negotiationType", "TYPE_RDP_NEG_FAILURE")))

# class NegotiationFailureCode(object):
#     """
#     @summary: Protocol negotiation failure code
#     """
#     SSL_REQUIRED_BY_SERVER = 0x00000001
#     SSL_NOT_ALLOWED_BY_SERVER = 0x00000002
#     SSL_CERT_NOT_ON_SERVER = 0x00000003
#     INCONSISTENT_FLAGS = 0x00000004
#     HYBRID_REQUIRED_BY_SERVER = 0x00000005
#     SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006
    
# class ServerConnectionConfirm(CompositeType):
#     """
#     @summary: Server response
#     @see: http://msdn.microsoft.com/en-us/library/cc240506.aspx
#     """
#     def __init__(self):
#         CompositeType.__init__(self)
#         self.len = UInt8(lambda:sizeof(self) - 1)
#         self.code = UInt8(MessageType.X224_TPDU_CONNECTION_CONFIRM, constant = True)
#         self.padding = (UInt16Be(), UInt16Be(), UInt8())
#         #read if there is enough data
#         self.protocolNeg = Negotiation(optional = True)
        
# class X224DataHeader(CompositeType):
#     """
#     @summary: Header send when x224 exchange application data
#     """
#     def __init__(self):
#         CompositeType.__init__(self)
#         self.header = UInt8(2)
#         self.messageType = UInt8(MessageType.X224_TPDU_DATA, constant = True)
#         self.separator = UInt8(0x80, constant = True)
    
# class Server(X224Layer):
#     """
#     @summary: Server automata of X224 layer
#     """
#     def __init__(self, presentation, privateKeyFileName = None, certificateFileName = None, forceSSL = False):
#         """
#         @param presentation: {layer} upper layer, MCS layer in RDP case
#         @param privateKeyFileName: {str} file contain server private key
#         @param certficiateFileName: {str} file that contain public key
#         @param forceSSL: {boolean} reject old client that doerasn't support SSL
#         """
#         X224Layer.__init__(self, presentation)
#         #Server mode informations for TLS connection
#         self._serverPrivateKeyFileName = privateKeyFileName
#         self._serverCertificateFileName = certificateFileName
#         self._forceSSL = forceSSL and not self._serverPrivateKeyFileName is None and not self._serverCertificateFileName is None
        
#     def connect(self):
#         """
#         @summary: Connection request for server wait connection request packet from client
#         """
#         self.setNextState(self.recvConnectionRequest)
        
#     def recvConnectionRequest(self, data):
#         """
#         @summary:  Read connection confirm packet
#                     Next state is send connection confirm
#         @param data: {Stream}
#         @see : http://msdn.microsoft.com/en-us/library/cc240470.aspx
#         """
#         message = ClientConnectionRequestPDU()
#         data.readType(message)
        
#         if not message.protocolNeg._is_readed:
#             self._requestedProtocol = Protocols.PROTOCOL_RDP
#         else:
#             self._requestedProtocol = message.protocolNeg.selectedProtocol.value
        
#         #match best security layer available
#         if not self._serverPrivateKeyFileName is None and not self._serverCertificateFileName is None:
#             self._selectedProtocol = self._requestedProtocol & Protocols.PROTOCOL_SSL
#         else:
#             self._selectedProtocol = self._requestedProtocol & Protocols.PROTOCOL_RDP
        
#         #if force ssl is enable
#         if not self._selectedProtocol & Protocols.PROTOCOL_SSL and self._forceSSL:
#             logger.warning("server reject client because doesn't support SSL")
#             #send error message and quit
#             message = ServerConnectionConfirm()
#             message.protocolNeg.code.value = NegociationType.TYPE_RDP_NEG_FAILURE
#             message.protocolNeg.failureCode.value = NegotiationFailureCode.SSL_REQUIRED_BY_SERVER
#             self._transport.send(message)
#             self.close()
#             return
        
#         self.sendConnectionConfirm()
        
#     def sendConnectionConfirm(self):
#         """
#         @summary:  Write connection confirm message
#                     Start TLS connection
#                     Next state is recvData
#         @see : http://msdn.microsoft.com/en-us/library/cc240501.aspx
#         """
#         message = ServerConnectionConfirm()
#         message.protocolNeg.code.value = NegociationType.TYPE_RDP_NEG_RSP
#         message.protocolNeg.selectedProtocol.value = self._selectedProtocol
#         self._transport.send(message)
#         if self._selectedProtocol == Protocols.PROTOCOL_SSL:
#             logger.debug("*" * 10 + " select SSL layer " + "*" * 10)
#             #_transport is TPKT and transport is TCP layer of twisted
#             self._transport.startTLS(ServerTLSContext(self._serverPrivateKeyFileName, self._serverCertificateFileName))
            
#         #connection is done send to presentation
#         self.setNextState(self.recvData)
#         self._presentation.connect()

#open ssl needed
# from twisted.internet import ssl
# from OpenSSL import SSL

# class ClientTLSContext(ssl.ClientContextFactory):
#     """
#     @summary: client context factory for open ssl
#     """
#     def getContext(self):
#         context = SSL.Context(SSL.TLSv1_METHOD)
#         context.set_options(SSL.OP_DONT_INSERT_EMPTY_FRAGMENTS)
#         context.set_options(SSL.OP_TLS_BLOCK_PADDING_BUG)
#         return context
    
# class ServerTLSContext(ssl.DefaultOpenSSLContextFactory):
#     """
#     @summary: Server context factory for open ssl
#     @param privateKeyFileName: Name of a file containing a private key
#     @param certificateFileName: Name of a file containing a certificate
#     """
#     def __init__(self, privateKeyFileName, certificateFileName):
#         class TPDUSSLContext(SSL.Context):
#             def __init__(self, method):
#                 SSL.Context.__init__(self, method)
#                 self.set_options(SSL.OP_DONT_INSERT_EMPTY_FRAGMENTS)
#                 self.set_options(SSL.OP_TLS_BLOCK_PADDING_BUG)

#         ssl.DefaultOpenSSLContextFactory.__init__(self, privateKeyFileName, certificateFileName, SSL.SSLv23_METHOD, TPDUSSLContext)
        