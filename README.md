Netscaler Cookie Decryptor
by @catalyst256

This python script will take a Citrix Netscaler persistence cookie and decrypt the values. This will allow you to determine the internal addresses of a Netscaler load balanced website. Typically Netscaler cookies start with NSC_

THis is an example of a Netscaler Cookie from the internet:

NSC_Qspe-xxx.bwjwb.dp.vl-IUUQ=ffffffff50effd8445525d5f4f58455e445a4a423660

You can then run this through the Netscaler Cookie Decryptor using from the command line:

nsccookiedecrypt.py NSC_Qspe-xxx.bwjwb.dp.vl-IUUQ=ffffffff50effd8445525d5f4f58455e445a4a423660

This would return you the following:

Server Name=Prod-www.xxxxx.co.uk-HTTP
Server IP=83.231.227.149
Server Port=80

This code will work on Windows (tested) and Linux (tested) and probably OSX (not tested).

Thanks to:
Alejandro Nolla Blanco - alejandro.nolla@gmail.com - @z0mbiehunt3r - for the inspiration to write this and for adding the error correction.
Daniel Grootveld - danielg75@gmail.com - @shDaniell - for helping with the XOR method of decryption, adding the service port decryption and for making my regex more robust.

