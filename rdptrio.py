#!/usr/bin/python
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
example of use rdpy as rdp client
"""

import sys, os, getopt, socket

# from PyQt5 import QtGui, QtCore, QtWidgets
# from rdpy.ui.qt5 import RDPClientQt
from rdptrio.protocol.rdp import rdp
# from rdptrio.core.layer import RawLayerClientFactory
import logging
from rdptrio.core.error import RDPSecurityNegoFail

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class RDPClientQtFactory():#RawLayerClientFactory):
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
        
    def buildObserver(self, controller, addr):
        """
        @summary:  Build RFB observer
                    We use a RDPClientQt as RDP observer
        @param controller: build factory and needed by observer
        @param addr: destination address
        @return: RDPClientQt
        """
        logger.debug('[RDPClientQtFactory/buildObserver] BuildObserver Init')
        
        controller.setUsername(self._username)
        controller.setPassword(self._passwod)
        controller.setDomain(self._domain)
        controller.setKeyboardLayout(self._keyboardLayout)
        controller.setHostname(socket.gethostname())
        if self._optimized:
            logger.debug("[RDPClientQtFactory/buildObserver] Using Performance Session")
            controller.setPerformanceSession()
            
        controller.setSecurityLevel(self._security)
            
    def buildProtocol(self, addr):
        """
        @summary: Function call from twisted
        @param addr: destination address
        """
        
        logger.debug('[RDPClientQtFactory/buildProtocol] BuildProtocol Init')
        
        controller = rdp.RDPClientController()
        
        self.buildObserver(controller, addr)
        rawLayer = controller.getProtocol()
        rawLayer.setFactory(self)
        return rawLayer
        
        
def autoDetectKeyboardLayout():
    """
    @summary: try to auto detect keyboard layout
    """
    try:
        if os.name == 'posix':    
            from subprocess import check_output
            result = check_output(["setxkbmap", "-print"])
            if 'azerty' in result:
                return "fr"
        elif os.name == 'nt':
            import win32api, win32con, win32process
            from ctypes import windll
            w = windll.user32.GetForegroundWindow() 
            tid = windll.user32.GetWindowThreadProcessId(w, 0) 
            result = windll.user32.GetKeyboardLayout(tid)
            log.info(result)
            if result == 0x40c040c:
                return "fr"
    except Exception as e:
        logging.info("failed to auto detect keyboard layout " + str(e))
        pass
    return "en"
        
def help():
    '''
        Usage: rdpy-rdpclient [options] ip[:port]"
        \t-u: user name
        \t-p: password
        \t-d: domain
        \t-w: width of screen [default : 1024]
        \t-l: height of screen [default : 800]
        \t-f: enable full screen mode [default : False]
        \t-k: keyboard layout [en|fr] [default : en]
        \t-o: optimized session (disable costly effect) [default : False]
        \t-r: rss_filepath Recorded Session Scenario [default : None]
    '''
     
if __name__ == '__main__':
    
    #default script argument
    username = ""
    password = ""
    domain = ""
    width = 1024
    height = 800
    fullscreen = False
    optimized = False
    recodedPath = None
    keyboardLayout = autoDetectKeyboardLayout()
    
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
    

    logging.info("keyboard layout set to %s"%keyboardLayout)
    
    # from twisted.internet import reactor

    # reactor.connectTCP(ip, int(port), RDPClientQtFactory(width, height, username, password, domain, fullscreen, keyboardLayout, optimized, "nego", recodedPath))
    client = RDPClientQtFactory(width, height, username, password, domain, fullscreen, keyboardLayout, optimized, "nego", recodedPath)
    # breakpoint()
    layer = client.buildProtocol(f'{ip}:{port}')