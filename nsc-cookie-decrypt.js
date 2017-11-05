#!/usr/bin/env node

/**
 * This is a simple javascript port of Adam's excellent python script for decrypting NetScaler cookies.
 * 
 * @author Sonny George
 * @license: GPL v2
 * @date: 04-11-2017
 */

/**
 * Parse Citrix NetScaler cookie
 * 
 * @param cookie: Citrix NetScaler cookie
 * @return: Returns ServiceName, ServerIP and ServerPort
 */ 
function parseCookie(cookie) {
    const searchPattern = /NSC_([a-zA-Z0-9\-\_\.]*)=[0-9a-f]{8}([0-9a-f]{8}).*([0-9a-f]{4})$/
    const parseResults = searchPattern.exec(cookie)

    if (!parseResults || parseResults.length < 4)
        throw 'Could not parse cookie'

    return {
        serviceName: parseResults[1], 
        serverIP: parseInt(parseResults[2], 16), 
        serverPort: parseInt(parseResults[3], 16)}
}

/**
 * Decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
 * 
 * @param cookie Citrix NetScaler cookie
 * @type cookie: String
 * @return: service name
 */
function decryptServiceName(serviceName) {
    // This decrypts the Caesar Subsitution Cipher Encryption used on the Netscaler Cookie Name
    const substitutions = {
        key:   'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        value: 'zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY'
    }

    return serviceName
        .split('')
        .reduce((name, character) => {
            const keyIndex = substitutions.key.indexOf(character)

            if (keyIndex >= 0) {
                return name += substitutions.value[keyIndex]
            } 
            
            return name += character
        }, '')
}

/**
 * Decrypts the XOR encryption used for the Netscaler Server IP
 * 
 * @param cookie Citrix NetScaler cookie
 * @type cookie: String
 * @return: XORed server IP based on ipkey
*/
function decryptServerIP(serverIP) {
    const ipKey = 0x03081e11
    const decodedIP = (serverIP ^ ipKey)
        .toString(16)       // convert integer to hex string
        .padStart(8, '0')   // pad hex string with left 0's to make 8 characters
    
    return decodedIP
        .match(/([a-f0-9]{2})/g)            // split hex into 2 character tokens
        .map(token => parseInt(token, 16))  // map each hex element to a decimal value
        .join('.')                          // join tokens by '.'
}

/**
 * Decrypts the XOR encryption used on the Netscaler Server Port
 * 
 * @param cookie Citrix NetScaler cookie
 * @type cookie: String
 * @return: XORed server port
*/
function decryptServerPort(serverPort) {
    const portKey = 0x3630
    const decodedPort = serverPort ^ portKey // no need to convert to hex since an integer will do for port
 
    return String(decodedPort)
}

/**
 * Make entire decryption of Citrix NetScaler cookie
 * 
 * @param cookie: Citrix NetScaler cookie
 * @return: Returns RealName, RealIP and RealPort
*/
function decryptCookie(cookie) {
    const {serviceName, serverIP, serverPort} = parseCookie(cookie)
    // console.log(parseCookie(cookie))

    return {
        realName: decryptServiceName(serviceName),
        realIP: decryptServerIP(serverIP),
        realPort: decryptServerPort(serverPort)
    }
}

function main() { 
    try {
        if (process.argv.length != 3) {
            const path = require('path');
    
            throw `usage: ${path.basename(process.argv[1])} net_scaler_cookie`
        }
    
        const cookie = process.argv[2]
        
        Object.entries(decryptCookie(cookie))
            .forEach(entry => console.log(`${entry[0].padEnd(9)}: ${entry[1]}`))
        
        process.exit(0)
    } catch (error) {
        console.log(error)
        process.exit(1)
    }    
} 

if (require.main === module) { 
    main(); 
}
