#!/usr/bin/env ruby
# 
# Ruby script to decrypt Citrix Netscaler Load Balancer Persistence Cookies
# 
# @Author: Sabri Saleh | @KINGSABRI
# Translated from: https://github.com/catalyst256/Netscaler-Cookie-Decryptor/
# 
# Usage: 
# ruby nsccookiedecrypt.rb <NetScalerCookie>
#
require 'ipaddr'

# Parse Citrix NetScaler cookie
# @param cookie [String]
#   Citrix NetScaler cookie
# @return [Array <String, Integer, Integer>]
#   array of servicename, serverip.hex, serverport.hex
def parse_cookie(cookie)
  pattern = /NSC_([[:print:]\-\_\.]*)=[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})$/
  parsed  = cookie.scan(pattern)    
  servicename, serverip, serverport = parsed.flatten unless parsed.nil?
  [servicename, serverip.hex, serverport.hex]
rescue 
  puts "[!] Couldn't parse cookie: #{cookie}"
  exit!
end

# Decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
# @param servicename [String]
#   Citrix NetScaler cookie (servicename part)
# @return [String]
def decrypt_service_name(servicename)
  trans = ['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ','zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY']
  servicename.tr(trans[0], trans[1])
end

# Decrypts the XOR encryption used for the Netscaler Server IP
# @param serverip [Integer]
#   Citrix NetScaler cookie (serverip part)
# @return [String] the decoded IP address
def decrypt_server_ip(serverip)
  ipkey = 0x03081e11
  decodedip = (serverip ^ ipkey).to_s(16).rjust(8, '0')
  IPAddr.new(decodedip.hex, Socket::AF_INET).to_s
end

# Decrypts the XOR encryption used for the Netscaler Server Port
# @param serverip [Integer]
#   Citrix NetScaler cookie (serverport part)
# @return [Integer] the decoded port
def decrypt_server_port(serverport)
  portkey = 0x3630
  decodedport = serverport ^ portkey
end

# Make entire decryption of Citrix NetScaler cookie
# @param cookie [String]
#   Citrix NetScaler cookie
# @return [Array <String, String, Integer>]
#   array of realname, realip, realport
def decrypt_cookie(cookie)
  servicename, serverip, serverport = parse_cookie(cookie)
  realname = decrypt_service_name(servicename)
  realip   = decrypt_server_ip(serverip)
  realport = decrypt_server_port(serverport)
  [realname, realip, realport]
end

if ARGV.empty?
  puts "USAGE: ruby #{__FILE__} <NetScalerCookie>" ; exit! 
end

cookie = ARGV[0]
realname, realip, realport = decrypt_cookie(cookie)
puts "[+] vServer Name: #{realname}"
puts "[+] vServer IP  : #{realip}"
puts "[+] vServer Port: #{realport}"
