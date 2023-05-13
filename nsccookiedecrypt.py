#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Netscaler Cookie Decryptor - decrypts Netscaler load balancer persistence cookies
Copyright (C) 2012  Adam Maxwell - catalyst256@gmail.com 
Nick: @catalyst256
Blog: itgeekchronicles.co.uk

Thanks to:
Alejandro Nolla Blanco - alejandro.nolla@gmail.com - @z0mbiehunt3r - for the inspiration to write this and for adding the error correction.
Daniel Grootveld - danielg75@gmail.com - @shDaniell - for helping with the XOR method of decryption, adding the service port decryption and for making my regex more robust.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

@author: Adam Maxwell
@license: GPL v2
@date: 23-01-2012
@version: 0.3.1

"""

import sys
import re
import string




def parseCookie(cookie):
    """Parse Citrix NetScaler cookie
    @param cookie: Citrix NetScaler cookie
    @return: Returns ServiceName, ServerIP and ServerPort
    """
    s = re.search('NSC_([a-zA-Z0-9\-\_\.]*)=[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})$',cookie)
    if s is not None:
        servicename = s.group(1) # first group is name ([a-z\-]*)
        serverip = int(s.group(2), 16)
        serverport = int(s.group(3), 16)
    else:
        raise Exception('Could not parse cookie')
    return servicename, serverip, serverport

def decryptServiceName(servicename):
    """Decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: service name
    """
    #This decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
    trans = str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ','zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY')
    realname = servicename.translate(trans)
    return realname
        
def decryptServerIP(serverip):
    """Decrypts the XOR encryption used for the Netscaler Server IP
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: XORed server IP based on ipkey
    """
    ipkey = 0x03081e11
    decodedip = hex (serverip ^ ipkey)
    t = decodedip[2:10].zfill(8)
    realip = '.'.join(str(int(i, 16)) for i in([t[i:i+2] for i in range(0, len(t), 2)]))
    return realip
        
def decryptServerPort(serverport):
    """Decrypts the XOR encryption used on the Netscaler Server Port
    @param cookie Citrix NetScaler cookie
    @type cookie: String
    @return: XORed server port
    """    
    portkey = 0x3630
    decodedport = serverport ^ portkey #no need to convert to hex since an integer will do for port
    realport = str(decodedport)
    return realport

def decryptCookie(cookie):
    """Make entire decryption of Citrix NetScaler cookie
    @param cookie: Citrix NetScaler cookie
    @return: Returns RealName, RealIP and RealPort
    """
    servicename, serverip, serverport = parseCookie(cookie)
    realname = decryptServiceName(servicename)
    realip = decryptServerIP(serverip)
    realport = decryptServerPort(serverport)
    return realname,realip,realport

if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("USAGE: %s NetScalerCookie" % sys.argv[0])
        sys.exit(1)
    
    cookie = sys.argv[1]
    realname,realip,realport = decryptCookie(cookie)
    
    print('vServer Name=%s' %realname)
    print('vServer IP=%s' %realip)
    print('vServer Port=%s' %realport)
