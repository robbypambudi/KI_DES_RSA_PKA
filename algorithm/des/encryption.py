
from .helper import str_to_bin, ip_on_binary_rep, binary_to_ascii
from .key import e_box_table, s_boxes, p_box_table, ip_inverse_table, generate_round_keys

def encryption(user_input):
  binary_rep_of_input = str_to_bin(user_input)
  round_keys = generate_round_keys()

  ip_result_str = ip_on_binary_rep(binary_rep_of_input)

  lpt = ip_result_str[:32]
  rpt = ip_result_str[32:]


  for round_num in range(16):
    expanded_result = [rpt[i - 1] for i in e_box_table]

    expanded_result_str = ''.join(expanded_result)

    round_key_str = round_keys[round_num]


    xor_result_str = ''
    for i in range(48):
      xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))


    six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

    s_box_substituted = ''

    # Apply S-box substitution for each 6-bit group
    for i in range(8):
      row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
      col_bits = int(six_bit_groups[i][1:-1], 2)

      # Lookup the S-box value
      s_box_value = s_boxes[i][row_bits][col_bits]
      
      # Convert the S-box value to a 4-bit binary string and append to the result
      s_box_substituted += format(s_box_value, '04b')

    # Apply a P permutation to the result
    p_box_result = [s_box_substituted[i - 1] for i in p_box_table]


    # Convert LPT to a list of bits for the XOR operation
    lpt_list = list(lpt)

    # Perform XOR operation
    new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

    # Convert the result back to a string for better visualization
    new_rpt_str = ''.join(new_rpt)

    # Update LPT and RPT for the next round
    lpt = rpt
    rpt = new_rpt_str

  final_result = rpt + lpt

  final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

  final_cipher_str = ''.join(final_cipher)

  final_cipher_ascii = binary_to_ascii(final_cipher_str)
  
  return final_cipher_ascii