# importfrom files key.py
from .key import ip_table

"""
Function for the conversion of string to binary of 64 bits:
"""
def str_to_bin(user_input):
  # Convert the string to binary
  binary_representation = ''
  
  for char in user_input:
      # Get ASCII value of the character and convert it to binary
      binary_char = format(ord(char), '08b')
      binary_representation += binary_char
      binary_representation = binary_representation[:64]
  
  # Pad or truncate the binary representation to 64 bits
  binary_representation = binary_representation[:64].ljust(64, '0')
  
  return binary_representation


""" 
Function for conversion of binary to ASCII:
"""
def binary_to_ascii(binary_str):
  ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
  return ascii_str

"""
  Function for implementation of initial permutation on the binary string:
"""
def ip_on_binary_rep(binary_representation):
    
    ip_result = [None] * 64
    
    for i in range(64):
        ip_result[i] = binary_representation[ip_table[i] - 1]

    # Convert the result back to a string for better visualization
    ip_result_str = ''.join(ip_result)
    
    return ip_result_str
