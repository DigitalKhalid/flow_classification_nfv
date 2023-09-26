import socket
import sys
import json


def register_vnf(data, ip, port):
    json_message = json.dumps(data)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    except socket.error:
        sys.exit()

    s.sendto(json_message.encode(encoding='utf_8'), (ip, port ))


if __name__ == '__main__':
    if len(sys.argv)<2:
        print("script input is missing.... python3 vnf_reg.py <input file name>")
        sys.exit()
        
    f = open(sys.argv[1])
    data = json.load(f)
    ip = sys.argv[2]
    port = sys.argv[3]

    print("vnf register data ", data)
    register_vnf(data, ip, port)
