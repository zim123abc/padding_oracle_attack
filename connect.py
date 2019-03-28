import socket
import math as m

def parse_encryption(x):
    temp1 = x.split("b'Encryption: ")
    temp2 = temp1[1].split("\\n")
    total_length = int(temp2[0])
    encrypted_string = list(temp2[1].split(" "))
    del encrypted_string[len(encrypted_string)-1]
    IV = (temp2[2].split("b'"))[1].split("'")[0]
    return total_length, encrypted_string, IV

def encryption_query(pad):
    query_txt = "-e " + pad
    r.send(query_txt.encode())     # Encryption of the secret message
    x = r.recv(1024).decode()
    return x

def encryption_query_parse(pad):
    x = encryption_query(pad)
    return parse_encryption(x)

def decryption_query(ciphertext, iv):
    query = "-V " + ciphertext + " " + iv
    r.send(query.encode()) # Valid ciphertext and IV
    x = r.recv(1024).decode()
    return x

def find_plaintext_length():
    x = encryption_query("")
    total_length, encrypted_string, IV = parse_encryption(x)
    temp_length = total_length
    counter = 1
    while (total_length == temp_length):
        pad = ""
        for i in range(counter):
            pad += "00"
        x = encryption_query(pad)
        temp_length, encrypted_string, IV = parse_encryption(x)
        counter += 1
    plaintext_length = (total_length - (counter-1)) - 16
    return plaintext_length, counter

def parse_into_blocks(encrypted_string):
    blocks = []
    j = 0
    i = 0
    while j < len(encrypted_string):
        i = 0
        tempstr = ""
        while i < 16:
            tempstr += encrypted_string[i+j]
            i += 1
        blocks.append(tempstr)
        j += 16
    return blocks

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
r.connect(("192.168.122.57", 31336))

print("Encryption of the secret message:\n")
r.send("-e".encode())     # Encryption of the secret message
x = r.recv(1024).decode()
print x

total_length, encrypted_string, IV = parse_encryption(x)

#====================== Print Encrypted Info =============================#
#print "\nTotal Length: ",
#print total_length
#print "Encrypted String: ",
#print encrypted_string
#print "IV: " + IV
#====================== End of Print =====================================#

#====================== Parse into Individual Blocks =====================#
#blocks = parse_into_blocks(encrypted_string)
#print "\nBlocks: ",
#print blocks
#====================== End of Parse ====================================#

#====================== Determine Length of Plain Text =================#
plaintext_length, prefix_padding = find_plaintext_length()
print "\nPlaintext Length: ",
print plaintext_length
#====================== End of Determining Block Length ==================#
plaintext = []
if plaintext_length % 16 != 0:
    pad = "00"*(16-plaintext_length)
else:
    pad = ''
print pad
start_block  = int(m.ceil(float(plaintext_length / 16.0))) #figure out what is the last block of the message
print "Last block of plaintext is ",
print start_block
start_block_index = start_block - 1
while True:
    total_length, encrypted_string, IV = encryption_query_parse(pad)
    blocks = parse_into_blocks(encrypted_string)
    blocks[len(blocks)-1] = blocks[start_block-1]
    ciphertext = "".join(blocks)
    success_flag = decryption_query(ciphertext, IV)
    if success_flag == "Valid":
        print "Blocks: ",
        print blocks
        print "IV: ",
        print IV
        break
    #print new_cipher_query

r.close()
