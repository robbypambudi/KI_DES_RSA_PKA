
from .key import e_box_table, s_boxes, p_box_table, ip_inverse_table, generate_round_keys
from .helper import ip_on_binary_rep, binary_to_ascii

def decryption(final_cipher):
  # Initialize lists to store round keys
  round_keys = generate_round_keys()
  
  # Apply Initial Permutation
  ip_dec_result_str = ip_on_binary_rep(final_cipher)
  
  lpt = ip_dec_result_str[:32]
  rpt = ip_dec_result_str[32:]

  for round_num in range(16):
    # Perform expansion (32 bits to 48 bits)
    expanded_result = [rpt[i - 1] for i in e_box_table]
    expanded_result_str = ''.join(expanded_result)
    round_key_str = round_keys[15-round_num]

    xor_result_str = ''
    for i in range(48):
      xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

    six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

    s_box_substituted = ''

    for i in range(8):
      row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
      col_bits = int(six_bit_groups[i][1:-1], 2)
      s_box_value = s_boxes[i][row_bits][col_bits]
      s_box_substituted += format(s_box_value, '04b')

    # Apply a P permutation to the result
    p_box_result = [s_box_substituted[i - 1] for i in p_box_table]

    # Convert the result back to a string for better visualization
    # p_box_result_str = ''.join(p_box_result)

    # Convert LPT to a list of bits for the XOR operation
    lpt_list = list(lpt)

    # Perform XOR operation
    new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

    # Convert the result back to a string for better visualization
    new_rpt_str = ''.join(new_rpt)

    # Update LPT and RPT for the next round
    lpt = rpt
    rpt = new_rpt_str

    # Print or use the RPT for each round
  
  # print('\n')
  final_result = rpt + lpt
  
  # Perform the final permutation (IP-1)
  final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

  # Convert the result back to a string for better visualization
  final_cipher_str = ''.join(final_cipher)

  # Print or use the final cipher

  # binary cipher string to ascii
  final_cipher_ascii = binary_to_ascii(final_cipher_str)
  # print("Decryption of Cipher :", final_cipher_ascii)

  return final_cipher_ascii