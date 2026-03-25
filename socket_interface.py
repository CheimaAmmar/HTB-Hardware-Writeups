import time
import numpy as np
import socket
import base64

# This might be useful with the exploitation of the device at some point!
#import lascar 

HOST = '0.0.0.0' # This must be changed to the corresponding value of the live instance
PORT = 1337  # This must be changed to the corresponding value of the live instance

# This function is used to decode the base64 transmitted power trace (which is a NumPy array)

# The function should only be called for the response of the 1. option and on the data received
# after we send the plaintext (as seen in the example code below)
def b64_decode_trace(leakage):
        byte_data = base64.b64decode(leakage) # decode base64
        return np.frombuffer(byte_data) # convert binary data into a NumPy array


# This function is used to communicate with the remote machine (Laptop-2) via socket
# The socket connection is also accessible with the use of netcat (nc)
def connect_to_socket(option, data):
        # Initialize a socket connection 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Connect to the HOST machine on the provided PORT
                s.connect((HOST, PORT))

                # Receive initial message
                resp_1 = s.recv(1024)

                # Select one of the two available options of this interface
                s.sendall(option) 

                # Receive response
                resp_2 = s.recv(1024)

                # Send the data 
                # option one: binary plaintext 
                # option two: Hex encoded AES KEY  
                s.sendall(data) 

                # Receive response
                # option one: receive base64 encoded binary data 
                # that represented the power traces as a Numpy array 

                # option two: receive an ASCII Message 
                # (if the key is correct the flag will be returned)
                resp_data = b''
                while True:
                        temp_data = s.recv(8096)
                        if not temp_data:
                                break
                        resp_data += temp_data
                s.close()

                # The print commands can be used for debugging in order to observe the responses
                # The following print commands can be commented out.
                print(resp_1.decode('ascii'))
                print(option)
                print(resp_2.decode('ascii'))
                print(data)
                #print(resp_data)

                return resp_data



# Sample binary plaintext
plaintext = b'0123456789ABCDEF'

# Example use of option 1 
print("Option 1:")
leakage = connect_to_socket(b'1', plaintext)
power_trace = b64_decode_trace(leakage)

print("Length of power trace: {}".format(power_trace.shape))
#print(power_trace) # Outputs the NumPy array that represents the power trace. 

# Always use a delay between each connection 
# in order to have a stable connection
time.sleep(0.1)

# Sample HEX encoded AES KEY
KEY = b'00112233445566778899AABBCCDDEEFF'

print("\nOption 2:")

# Example use of option 2
response = connect_to_socket(b'2', KEY)
print(response)
