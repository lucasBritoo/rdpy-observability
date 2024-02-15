import sys, getopt
from rdptrio.protocol.rdp import rdp
import logging
import trio
import ssl
from rdptrio.core.type import StreamBuffer

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG)

class RDPClientQtFactory():
    """
    @summary: Factory create a RDP GUI client
    """
    def __init__(self, width, height, username, password, domain, fullscreen, keyboardLayout, optimized, security, recodedPath):
        """
        @param width: {integer} width of client
        @param heigth: {integer} heigth of client
        @param username: {str} username present to the server
        @param password: {str} password present to the server
        @param domain: {str} microsoft domain
        @param fullscreen: {bool} show widget in fullscreen mode
        @param keyboardLayout: {str} (fr|en) keyboard layout
        @param optimized: {bool} enable optimized session orders
        @param security: {str} (ssl | rdp | nego)
        @param recodedPath: {str | None} Rss file Path
        """
        logger.debug('[RDPClientQtFactory]')
        self._width = width
        self._height = height
        self._username = username
        self._passwod = password
        self._domain = domain
        self._fullscreen = fullscreen
        self._keyboardLayout = keyboardLayout
        self._optimized = optimized
        self._nego = security == "nego"
        self._recodedPath = recodedPath
        
        if self._nego:
            #compute start nego nla need credentials
            if username != "" and password != "":
                logger.debug('[RDPClientQtFactory] Using RDP_LEVEL_NLA')
                self._security = rdp.SecurityLevel.RDP_LEVEL_NLA
            else:
                logger.debug('[RDPClientQtFactory] Using RDP_LEVEL_SSL')
                self._security = rdp.SecurityLevel.RDP_LEVEL_SSL
        else:
            logger.debug(f'[RDPClientQtFactory] Using {security}')
            self._security = security
        self._w = None
              
    def buildProtocol(self, addr):
        """
        @summary: Function call from twisted
        @param addr: destination address
        """
        
        logging.info('[RDPClientQtFactory] [buildProtocol()]')

        self.controller = rdp.RDPClientController()
        
        # controller.setUsername(self._username)
        # controller.setPassword(self._passwod)
        # controller.setDomain(self._domain)
        # controller.setKeyboardLayout(self._keyboardLayout)
        # controller.setHostname(socket.gethostname())
        # if self._optimized:
        #     logger.debug("[RDPClientQtFactory/buildObserver] Using Performance Session")
        #     controller.setPerformanceSession()
            
        # controller.setSecurityLevel(self._security)
        
        # self.controller = controller
        # rawLayer = controller.getProtocol()
        # rawLayer.setFactory(self)
        # return rawLayer
    
    async def sendX224(self, client_stream):
        await self.controller.sendConnectionRequestPDU(client_stream)
        await trio.sleep(1)
        # self.controller._x224Layer.connect()
        # self.controller._x224Layer.sendConnectionRequest()
        
    async def sender(self, client_stream, packets):
        
        while(True):
            packet = packets.getPacket()
            buffer = StreamBuffer()
            
            if packet:
                
                countBytes = 0
                for frame in packet:
                    frameValue = frame._value

                    if not isinstance(frameValue, bytes):
                        for frameInternal in frameValue:
                            buffer.append(frameInternal._value)
                            logger.debug(f"Name: {frameInternal._name}")
                            logger.debug(f"Frame: {frameInternal}")
                            logger.debug(f"Value: {frameInternal._value}")
                            countBytes += frameInternal._size

                    else:
                        buffer.append(frameValue)
                        logger.debug(f"Name: {frame._name}")
                        logger.debug(f"Frame: {frame}")
                        logger.debug(f"Value: {frameValue}")
                        countBytes += frame._size
                
                logger.debug(f"Stream Buffer: {buffer.getBuffer()}")
                await client_stream.send_all(buffer.getBuffer())
                logger.debug(f"Stream Buffer Size: {countBytes}")
                #await self.controller.sendConnectionRequestPDU(client_stream)
            
            await trio.sleep(1)
   
    
    async def receiver(self,client_stream):
            try:
                async for data in client_stream:
                    print(f"receiver: got data {data}")
                    self.controller._tpktLayer.readHeader(data)
                    sys.exit()
                print("receiver: connection closed")
            except trio.BrokenResourceError:
                pass
    # async def receiver(self, client_stream):
    #     try:
    #         received_data = bytearray()
    #         while len(received_data):
    #             chunk = await client_stream.receive_some(num_bytes - len(received_data))
    #             if not chunk:
    #                 break  # Se não houver mais dados, sai do loop
    #             received_data.extend(chunk)

    #         print(f"receiver: got data {received_data!r}")
    #         # Restante da lógica para processar os dados recebidos

    #     except trio.BrokenResourceError:
    #         pass
    #     except trio.EndOfChannel:
    #         print("receiver: connection closed")
        
async def main():
    #default script argument
    username = ""
    password = ""
    domain = ""
    width = 1024
    height = 800
    fullscreen = False
    optimized = False
    recodedPath = None
    keyboardLayout = "en"
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hfou:p:d:w:l:k:r:")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt == "-u":
            username = arg
        elif opt == "-p":
            password = arg
        elif opt == "-d":
            domain = arg
        elif opt == "-w":
            width = int(arg)
        elif opt == "-l":
            height = int(arg)
        elif opt == "-f":
            fullscreen = True
        elif opt == "-o":
            optimized = True
        elif opt == "-k":
            keyboardLayout = arg
        elif opt == "-r":
            recodedPath = arg
            
    if ':' in args[0]:
        ip, port = args[0].split(':')
    else:
        ip, port = args[0], "3389"
    
    client = RDPClientQtFactory(width, height, username, password, domain, fullscreen, keyboardLayout, optimized, "nego", recodedPath)
    layer = client.buildProtocol(f'{ip}:{port}')
    
    client_stream = await trio.open_tcp_stream(ip, int(port))
    
    # ssl_context = ssl.create_default_context()
    # ssl_context.check_hostname = False
    # ssl_context.verify_mode = ssl.CERT_NONE
    # client_stream = trio.SSLStream(tcp_stream, ssl_context=ssl_context)
    # await client_stream.do_handshake()
    client.controller.sendConnect()
    
    async with client_stream:
        async with trio.open_nursery() as nursery:

            nursery.start_soon(client.receiver, client_stream)
            
            nursery.start_soon(client.sender, client_stream, client.controller._sendQueue)
            # nursery.start_soon(client.sendX224, client_stream)

            
            
if __name__ == '__main__':
    
    
    trio.run(main)
    # client.sendX224()
    # client.controller._x224Layer.connect()
    
