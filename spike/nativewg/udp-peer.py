# Run transiently inside node-1; no files or WARP settings are changed.
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('100.96.0.2', 8082))
s.settimeout(180)
while True:
    try:
        data, addr = s.recvfrom(65535)
    except TimeoutError:
        break
    if data == b'exit-nativewg-spike':
        break
    s.sendto(data, addr)
s.close()
