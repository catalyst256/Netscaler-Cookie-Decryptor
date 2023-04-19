import re

import string

from string import ascii_letters

 

def parseCookie(cookie):

    """Parse Citrix NetScaler cookie

    @param cookie: Citrix NetScaler cookie

    @return: Returns ServiceName, ServerIP and ServerPort

    """

    s = re.search(

        'NSC_([a-zA-Z0-9\-\_\.]*)=[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})$', cookie)

    if s is not None:

        servicename = s.group(1)  # first group is name ([a-z\-]*)

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

    # This decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name

    trans = str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',

                          'zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY')

    realname = servicename.translate(trans)

    return realname

 

def decryptServerIP(serverip):

    """Decrypts the XOR encryption used for the Netscaler Server IP

    @param cookie Citrix NetScaler cookie

    @type cookie: String

    @return: XORed server IP based on ipkey

    """

    ipkey = 0x03081e11

    decodedip = hex(serverip ^ ipkey)

    t = decodedip[2:10].zfill(8)

    realip = '.'.join(str(int(i, 16))

                      for i in ([t[i:i+2] for i in range(0, len(t), 2)]))

    return realip

 

def decryptServerPort(serverport):

    """Decrypts the XOR encryption used on the Netscaler Server Port

    @param cookie Citrix NetScaler cookie

    @type cookie: String

    @return: XORed server port

    """

    portkey = 0x3630

    # no need to convert to hex since an integer will do for port

    decodedport = serverport ^ portkey

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

    return realname, realip, realport

 

if __name__ == '__main__':

    # Open the input file for reading

    with open('input.txt', 'r') as f:

        # Read the lines of input from the file

        lines = f.readlines()

 

    # Open the output file for writing

    with open('output.txt', 'w') as f:

        # Process each line and write the output to the file

        for line in lines:

            # Strip the newline character from the line

            line = line.strip()

            realname, realip, realport = decryptCookie(line)

            f.write(

                f'NSC: {line}\n'

                f'vServer Name={realname}\nvServer IP={realip}\nvServer Port={realport}\n\n')
