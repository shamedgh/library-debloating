import re
import sys

def cleanLib(libName):
    if ( ".so" in libName ):
        libName = re.sub("-[0-9][0-9.]*\.so",".so",libName)
        libName = libName[:libName.index(".so")]
    return libName

if __name__ == '__main__':
    print("input: ", sys.argv[1], " output: ", cleanLib(sys.argv[1]))
