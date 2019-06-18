#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
import sys
import struct
import json
import base64
from M2Crypto import RSA, BIO
from Crypto.Cipher import AES
import hashlib
from ctypes import *
 
# 修改为下载脚本的设备的XXXX设备号
CONF_DEVID = '8bd1553eb8b6749f1296e7c84d61e1cb'
 
DESC_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzwyG5Ag2AnoAab+87ZJS
/h7Jh4ZyIgH3JTbQTW1nsxuP/dNpa0uHqNkFjgN6QETVin3WTP/nTQt0PqKlJn9T
b8O8R+0iP1pGtacENd8iiUoNc1ts8Pu29IyFrQTnT+CG2eb4EVVNSwYXKyQeQirL
ohNDE5ld+dnjQlMDcKZCdlveb6T722qJ6pYSvxi7D5yVCdaAmHCXzNEWpYizon5d
xDJlhXZsyTPJmkvYWaxkhK0oIU4Sb/cJBLgBT9VmQGLuCNK3UzZmR7rzoHj70aVD
c9nKSUu7RD9chYWJaz61dehfgG8eNF6kOSnW83J+4dPi6miEsGcN/5PTM+MX/ddm
iQIDAQAB
-----END PUBLIC KEY-----
"""
 
 
DESC2_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwou77AwwI0tWq7cNQPNW
Lrk1rctbrkjCuObDBcU0fjqh5bWjDGU/FfgBR0/j5Y6DU+3RW2eEYdOmnd6Cc0C0
D2hncza6qIJAH8tMHPlJ0yLQ5Mylo8wXfQQY+/pCxDTJwSBBBeP76mdZr+7pOR73
eBU+kju0hh2ZblDTNkxdwJirl6QDF9s1F2zt34iljzJsiofftYxHvhQ1rIcH2nwG
lQsi7DZ2OArYra7AaFYtMHYW5QVvHAhoDT9TsGQZDd7lK4MBiMpD5fESoawPrBOA
VgHpBoMNcmri+fQlKo6Y3S9tkUVUPhOBuw6putdVZ1OV/B7iasqOoB0IxMk7zyG0
SQIDAQAB
-----END PUBLIC KEY-----
"""
 
DEV_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxHC5suX8aH0gYr6TVSFr
QQoJBsChjBtdU5FPt0dGiRwKFLl/OmabYYs6hsBAhCefLwa3PUt4stj9/L8FbTPC
T9x0nWV3Mf9TlQypd1rG8rtEl1z/LY30SA8O3sx3Lof0gSFtWezenLkM/+g9EpKV
nqMhPa9o/FKDklnWXwIvC7BHBkfBmN70tO7+G9f515zw3uyD3PJSEYPXLfXHzHDk
o+TpyJs2hXny209hZJ/JgQtphj6PB8TmmV9OK7MCKfiVnUvJoVHX9CeIGz4mt7uU
c312wOVLvM02LGm6t5z0ZUYk+GuzeKTYGibhrZb4nmg9pjRt/xgHq//kNgThXXyb
RwIDAQAB
-----END PUBLIC KEY-----
"""
 
TIMING_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCtDoGMRworNLQiCtErV
TkGufbeDgFC3I8vv+xBa6CyqMhe/kGhFpWpxey9qCboE3lPnBOKDuskI4GWX3V5T
ZLdYlIkJfSpf0TCEbZI1y0amZNOtHegclGYmadYYkb7VhPBfYDU/jdoPCoJqZaX1
6+VO4cfeHeHkaNYaHSLmfL6lMe1Fp2Lj9xo449zQC15o4b1CiaygCdWR6+ijSE0T
MXQ0O4U5eQ3i/9Hf0L5azojuZrGeKePz5+D2saprQhJn9Vun1bFhqpDuGPVi5iix
MBfSq/WUSmMAR4ReZpIq4K79TN1xYQd7vQYydnTZ7tycVDtU+fBRXWGrlrSif2Ak
6QIDAQAB
-----END PUBLIC KEY-----
"""
 
 
def printSep(title):
    print('\n' * 2 + '=' * 50 + title + '=' * 50)
 
 
def hexPrint(title, data, raw=False):
    print('>' * 10 + title + '<' * 10)
    if raw:
        print(data)
    print(' '.join(['0x%02x' % ord(x) for x in data]))
 
 
def decodeString(encString):
    outStr = ''
    outPos = 0
    for idx in range(32, len(encString) - 32, 2):
        ch = encString[idx:idx + 2]
        num = int(ch, 16)
 
        if (outPos ^ 0xFFFFFFFC) & outPos:
            outStr += chr(num & 0xFFFFFF04 | ~num & 0xFB)
        else:
            outStr += chr((num & 0x85 | ~num & 0x7A) ^ 0xCA)
 
        outPos += 1
 
    print('[RAW]: ' + encString)
    print('[OUT]: ' + outStr)
    return outStr
 
 
def dumpDecodeString():
    decodeString(
        'b5a22e63d115746d924c2550b9d5db43c39e898dd9989eadd197929f2a85c1a317d7a396afe9b5b9b38049d7')
 
    decodeString(
        '6b70c0c6c6e0fd916f2944eddb9fe4b49fba8b8bdc92989ac4929495c3d4af94c59893a8c089928fd5d59a8bc0d49f9ec398c9a4d290d58bde9cd8eeb949cc305df1e2d955c715db8094')
 
    decodeString(
        '8cae7678e306661f17263e1b3d94bcf49fba8b8bdc92989ac4929495c3d4af94c59893a8c089928fd5d59a8bc0d48f88ef8f9296d9959cd5c0959c6635fd599a9beaa4809b41b2cedb8fae')
 
    decodeString('29ac0816467fe8f159ea0ca9451de1afd88f8f8bc3c1d4d4c38f9489d59a8e8fd8d58f94c5989388c089928fd5d5959ec4d49a8bd9d49a8ec4930d498b51934a335b2a815226c6fe5238')
    decodeString('f9a8c9fc9db74bc6429fb6530aeb948b9fba8b8bdc92989ac4929495c3d4af94c59893a8c089928fd5d59a8bc0d4afa8f49a9e96df95b2d1c0d42bd661249b42b859c19bbd3d')
    decodeString(
        '20d519dcd962f889a01a91b52f561c38c39e898dd9989eb6d4cec8cca53c9ca24c17f32bd649dcbfbd4c')
    decodeString('974368d43e9f1b054b60c3155b2ccd7ad88f8f8bc3c1d4d4c38f9489d59a8e8fd8d58f94c5989388c089928fd5d5959ec4d49a8bd9d48f88d18e8f9339fd327b6193c98401998201db2aafd8')
 
 
def rsaDecodeWithKey(data, pubkey):
    bio = BIO.MemoryBuffer(pubkey)
    rsa = RSA.load_pub_key_bio(bio)
    return rsa.public_decrypt(data, RSA.pkcs1_padding)
 
 
def rsaDecodeWithDescKey(data):
    return rsaDecodeWithKey(data, DESC_PUBKEY)
 
 
def rsaDecodeWithDesc2Key(data):
    return rsaDecodeWithKey(data, DESC2_PUBKEY)
 
 
def rsaDecodeWithDevKey(data):
    return rsaDecodeWithKey(data, DEV_PUBKEY)
 
 
def rsaDecodeWithTimingKey(data):
    return rsaDecodeWithKey(data, TIMING_PUBKEY)
 
 
def getDeviceID():
    # 替换为你的XXXX设备号
    hexDeviceID = CONF_DEVID
    binDeviceID = ''
    for idx in range(0, len(hexDeviceID), 2):
        binDeviceID += chr(int(hexDeviceID[idx:idx + 2], 16))
    return binDeviceID
 
 
def aesDecodeWithKey(data, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(data).strip(chr(0))
 
 
def aesDecodeWithDeviceID(data):
    return aesDecodeWithKey(data, getDeviceID())
 
 
def dumpMD5(data):
    md = hashlib.md5()
    md.update(data)
    print('calc md5: [%s]' % md.hexdigest())
 
 
class TSPDataDict(object):
 
    def __init__(self, block, f):
        self.magic, self.index, self.start, self.end, self.len = struct.unpack(
            '4siiii', block)
        f.seek(self.start)
        self.data = f.read(self.end - self.start + 1)
 
        printSep(self.magic[:3] + ' BLOCK')
        print('  index: %d' % self.index)
        print('  start: %d' % self.start)
        print('    end: %d' % self.end)
        print('    len: %d' % self.len)
 
 
class TSPFileInfo(object):
    """
    00000000 TSPFileInfo     struc  (sizeof=0x54, align=0x4, copyof_524)
    00000000 NSObject_opaque DCB 4 dup(?)
    00000004 _header         tsp_header                -- char[6]
    0000000A                 DCB ?  undefined
    0000000B                 DCB ?  undefined
    0000000C _fileBlock       vector_tsp_data_dict      -- vector<char[20]>
    00000018 _descData       tsp_data_dict ?           -- char[20]
    0000002C _dirBlock        tsp_data_dict ?           -- char[20]
    00000040 _rsaDescData    tsp_data_dict ?           -- char[20]
    00000054 TSPFileInfo     ends
    """
 
    def __init__(self, path, tspKey):
        self.f = file(path, 'rb')
 
        self.header = None
        self.desBlock = None
        self.dseBlock = None
        self.steBlock = None
        self.fileBlock = []
        self.dirBlock = None
        self.tspKey = tspKey
 
        self.decodeDES = None
        self.decodeDSE = None
        self.decodeSTE = None
        self.decodeDIR = None
 
    def readBlockInfo(self):
        self.f.seek(0)
        data = self.f.read(6)
        self.header = data
 
        pos = 6
 
        while True:
            self.f.seek(pos)
            data = self.f.read(20)
 
            if data[:3] == 'END':
                return
            elif data[:3] == 'DES':
                self.desBlock = TSPDataDict(data, self.f)
            elif data[:3] == 'DSE':
                self.dseBlock = TSPDataDict(data, self.f)
            elif data[:3] == 'STE':
                self.steBlock = TSPDataDict(data, self.f)
            elif data[:3] == 'FIL':
                self.fileBlock.append(TSPDataDict(data, self.f))
            elif data[:3] == 'DIR':
                self.dirBlock = TSPDataDict(data, self.f)
            pos += 20
 
    def dumpDES(self):
        printSep('DES')
        self.decodeDES = self.desBlock.data
        print(self.decodeDES)
 
    def dumpDSE(self):
        printSep('DSE')
        print(self.dseBlock.data)
 
        jsonDict = json.loads(self.dseBlock.data)
 
        baseKey = base64.b64decode(jsonDict['key'])
        baseData = base64.b64decode(jsonDict['data'])
        baseMD5 = base64.b64decode(jsonDict['md5'])
 
        decodeKey = rsaDecodeWithKey(baseKey, DESC_PUBKEY)
        decodeData = aesDecodeWithKey(baseData, decodeKey)
        decodeMD5 = rsaDecodeWithKey(baseMD5, DESC_PUBKEY)
 
        print('decode key: [%s]' % decodeKey)
        print('decode data: [%s]' % decodeData)
        print('decode md5: [%s]' % decodeMD5)
        dumpMD5(decodeData)
 
        self.decodeDSE = decodeData
 
    def dumpSTE(self):
        printSep('STE')
        print(self.steBlock.data)
 
        jsonDict = json.loads(self.steBlock.data)
 
        baseKey = base64.b64decode(jsonDict['key'])
        baseData = base64.b64decode(jsonDict['data'])
        baseMD5 = base64.b64decode(jsonDict['md5'])
 
        decodeKey = rsaDecodeWithKey(baseKey, DESC_PUBKEY)
        decodeKey = aesDecodeWithKey(decodeKey, self.tspKey)
        decodeData = aesDecodeWithKey(baseData, decodeKey)
        decodeMD5 = rsaDecodeWithKey(baseMD5, DESC_PUBKEY)
 
        print('decode key: [%s]' % decodeKey)
        print('decode data: [%s]' % decodeData)
        print('decode md5: [%s]' % decodeMD5)
        dumpMD5(decodeData)
 
        self.decodeSTE = decodeData
 
    def __getFILName(self, idx):
        paths = json.loads(self.decodeDIR)['paths']
        for name, index in paths.items():
            if index == idx:
                return name
        return 'UNKNOWN'
 
    def __getFILLuaType(self, data):
        if data[1:4] == 'Lua' or data[1:3] == 'TS':
            return data[1:4]
        return 'UNKNOWN'
 
    def __dumpFIL(self, block):
        decodeData = aesDecodeWithKey(block.data, self.tspKey)
        padding = block.len - len(decodeData)
 
        path = '%d_%s_%s' % (block.index, self.__getFILLuaType(
            decodeData), self.__getFILName(block.index))
 
        f = file(path, 'wb')
        f.write(decodeData)
        if padding:
            f.write(chr(0) * padding)
        f.close()
 
        print('Write to %s, length %d, padding %d' %
              (path, len(decodeData), padding))
 
    def dumpFIL(self):
        printSep('FIL')
 
        idx = 1
        for block in self.fileBlock:
            printSep('FIL %d' % idx)
            self.__dumpFIL(block)
            idx += 1
 
    def dumpDIR(self):
        printSep('DIR')
        decodeData = aesDecodeWithKey(self.dirBlock.data, self.tspKey)
        print(decodeData)
        self.decodeDIR = decodeData
 
    def parse(self):
        self.readBlockInfo()
        self.dumpDES()
        self.dumpDSE()
        self.dumpSTE()
        self.dumpDIR()
        self.dumpFIL()
 
 
def __parseOutTspKey(path):
    data = file(path, 'r').read()
    print(data)
 
    jsonDict = json.loads(data)
 
    baseKey = base64.b64decode(jsonDict['key'])
    baseData = base64.b64decode(jsonDict['data'])
 
    decodeKey = rsaDecodeWithDevKey(baseKey)
    decodeKey = aesDecodeWithDeviceID(decodeKey)
    decodeData = aesDecodeWithKey(baseData, decodeKey)
 
    print('decode key: [%s]' % decodeKey)
    print('decode data: [%s]' % decodeData)
 
    return decodeData
 
 
def __parseInnerTspKey(data):
    print(data)
 
    jsonDict = json.loads(data)
 
    baseKey = base64.b64decode(jsonDict['1'])
    baseData = base64.b64decode(jsonDict['2'])
 
    decodeKey = rsaDecodeWithDesc2Key(baseKey)
    decodeKey = aesDecodeWithDeviceID(decodeKey)
    decodeData = aesDecodeWithKey(baseData, decodeKey)
 
    print('decode key: [%s]' % decodeKey)
    print('decode data: [%s]' % decodeData)
 
    return decodeData
 
 
def parseTspKey(path):
    innerData = __parseOutTspKey(path)
    innerJson = json.loads(__parseInnerTspKey(innerData))
    baseKey = base64.b64decode(innerJson['key'])
    hexPrint('tsp key', baseKey)
    return baseKey
 
 
def main():
    printSep('DECODE STRING')
    dumpDecodeString()
 
    # 该文件运行一次脚本后，在XXXX的脚本目录的tmp目录下可以找到，保存对应tsp脚本的加密key
    printSep('DECODE tsp4870.key')
    tspKey = parseTspKey('tsp7356.key')
 
    printSep('DECODE 4870.tsp')
    TSPFileInfo('7356.tsp', tspKey).parse()
 
if __name__ == '__main__':
    main()