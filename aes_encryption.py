from aes_base_tables import base_sbox, base_rcon

class AES_Encryption:
    def __init__(self, key_bytes):

        # Initialize base vectors
        self.s_box = base_sbox.copy()
        self.rcon = base_rcon.copy()

        # Key expansion
        key = self._convert_to_4x4_matrix(key_bytes)
        self.all_words = self._key_expansion(key)

        # Generate inverse s-box
        self.inv_box = [0] * 256
        for i in range(256):
            sbox_value = self.s_box[i]
            self.inv_box[sbox_value] = i

    
    #Helpers
    def _xtime(self, b):
        if b & 0x80:
            return ((b << 1) ^ 0x1b) & 0xFF
        return (b << 1) & 0xFF
    
    def _mul_2(self, x):
        return self._xtime(x)

    def _mul_3(self, x):
        return self._xtime(x) ^ x

    def _mul_9(self, x):
        return self._xtime(self._xtime(self._xtime(x))) ^ x

    def _mul_11(self, x):
        return self._xtime(self._xtime(self._xtime(x))) ^ self._xtime(x) ^ x

    def _mul_13(self, x):
        return self._xtime(self._xtime(self._xtime(x))) ^ self._xtime(self._xtime(x)) ^ x

    def _mul_14(self, x):
        return self._xtime(self._xtime(self._xtime(x))) ^ self._xtime(self._xtime(x)) ^ self._xtime(x)

    
    # Bytes substitution and inverse version
    def _sub_bytes(self, state, s_box):
        for i in range(0, len(state)):
            for j in range(0, len(state[i])):
                state[i][j] = s_box[state[i][j]]
        return state
    
    def _inv_sub_bytes(self, state, inv_s_box):
        for i in range(0, len(state)):
            for j in range(0, len(state[i])):
                state[i][j] = inv_s_box[state[i][j]]
        return state

    # Shiftrows and inverse version
    def _shiftrows(self, arr):
        counter = 1
        for i in range(1, 4):
            row = arr[i]
            arr[i] = row[counter:] + row[:counter]
            counter += 1
        return arr

    def _inv_shiftrows(self, arr):
        counter = 1
        for i in range(1, 4):
            row = arr[i]
            arr[i] = row[-counter:] + row[:-counter]
            counter += 1
        return arr

    # MixColumns step and inverse
    def _mix_columns(self, column):
        nb0 = self._xtime(column[0]) ^ (self._xtime(column[1]) ^ column[1]) ^ column[2] ^ column[3]
        nb1 = column[0] ^ self._xtime(column[1]) ^ (self._xtime(column[2]) ^ column[2]) ^ column[3]
        nb2 = column[0] ^ column[1] ^ self._xtime(column[2]) ^ (self._xtime(column[3]) ^ column[3])
        nb3 = (self._xtime(column[0]) ^ column[0]) ^ column[1] ^ column[2] ^ self._xtime(column[3])

        return [nb0, nb1, nb2, nb3]
    
    def _inv_mix_columns(self, col):
        n0 = self._mul_14(col[0]) ^ self._mul_11(col[1]) ^ self._mul_13(col[2]) ^ self._mul_9(col[3])
        n1 = self._mul_9(col[0]) ^ self._mul_14(col[1]) ^ self._mul_11(col[2]) ^ self._mul_13(col[3])
        n2 = self._mul_13(col[0]) ^ self._mul_9(col[1]) ^ self._mul_14(col[2]) ^ self._mul_11(col[3])
        n3 = self._mul_11(col[0]) ^ self._mul_13(col[1]) ^ self._mul_9(col[2]) ^ self._mul_14(col[3])
        return [n0, n1, n2, n3]


    def _start_mix(self, state, mode="normal"):
        for i in range(0, 4):
            column = []
            for j in range(0,4):
                column.append(state[j][i])

            if mode == "normal":
                new_column = self._mix_columns(column)
            if mode == "inversed":
                new_column = self._inv_mix_columns(column)

            for j in range(0,4):
                state[j][i] = new_column[j]

        return state
            
    def _add_round_key(self, state, key):
        for i in range(0,4):
            for j in range(0,4):
                state[i][j] = state[i][j] ^ key[i][j]
        return state

    # Conversions
    def _convert_to_4x4_matrix(self, arr):
        new_arr = [[], [], [], []]
        row = 0
        for c in arr:
            new_arr[row].append(c)
            row += 1
            if row > 3: row = 0
        return new_arr

    def _convert_words_to_matrix(self, words):
        matrix = [[],[],[],[]]
        if len(words) != 4:
            return "An error has ocurred."
        for i in range(0,4):
            for j in range(0,4):
                matrix[j].append(words[i][j])
        return matrix

     #Key expansion
    def _key_expansion(self, key):
        words= []
        r_con_counter = 0
        for i in range(0,4):
            word = []
            for j in range(0,4):
                word.append(key[j][i])
            words.append(word)

        for i in range(4,44):

            if i % 4 == 0:
                last_word = words[i-1].copy()
                new_word = last_word[1:] + last_word[:1]

                for j in range(4):
                    new_word[j] = self.s_box[new_word[j]]

                new_word[0] ^= int(self.rcon[r_con_counter], 16)
                r_con_counter += 1
                
                for j in range(4):
                    new_word[j] ^= words[i-4][j]

                words.append(new_word)
            else:
                last_word = words[i-1]
                four_behind = words[i-4]
                new_word = []
                for j in range(4):
                    new_word.append(last_word[j] ^ four_behind[j])
                words.append(new_word)
        return words

    def matrix_to_bytes(self, matrix):
        plain_text = []
        for i in range(4):
            for j in range(4):
                plain_text.append(matrix[j][i])
        return bytes(plain_text)
    
    # ENCRYPTION CALL
    def encrypt(self, plain_text_bytes):

        state = self._convert_to_4x4_matrix(plain_text_bytes)

        # Get fist key a XOR with base text (Step 0)
        first_key = self._convert_words_to_matrix(self.all_words[0:4])
        state = self._add_round_key(state, first_key)

        # Run steps 1 to 10 of AES algorithm
        for r in range(1, 10):
            state = self._sub_bytes(state, self.s_box)
            state = self._shiftrows(state)
            state = self._start_mix(state)

            round_key_matrix = self._convert_words_to_matrix(self.all_words[r*4: r*4+4])
            state = self._add_round_key(state, round_key_matrix)

        # Run step 11
        state = self._sub_bytes(state, self.s_box)
        state = self._shiftrows(state)
        final_key_matrix = self._convert_words_to_matrix(self.all_words[40:44])
        state = self._add_round_key(state, final_key_matrix)
        return state

    #DECRYPTION CALL
    def decrypt(self, cipher_text):
        state = [row[:] for row in cipher_text]


        fist_key = self._convert_words_to_matrix(self.all_words[40:44])
        state = self._add_round_key(state, fist_key)

        for r in range(9, 0, -1):
            # Inverted sub_bytes and shiftrows
            state = self._inv_shiftrows(state)
            state = self._inv_sub_bytes(state, self.inv_box)

            round_key_matrix = self._convert_words_to_matrix(self.all_words[r*4: r*4+4])
            state = self._add_round_key(state, round_key_matrix)

            state = self._start_mix(state, mode="inversed") 

        state = self._inv_shiftrows(state)
        state = self._inv_sub_bytes(state, self.inv_box)
        final_key_matrix = self._convert_words_to_matrix(self.all_words[0:4])
        state = self._add_round_key(state, final_key_matrix)
        return state
    
    def test():
        aes = AES_Encryption(b"Thats my Kung Fu")
        cipher = aes.encrypt(b"Two One Nine Two")
        expected_cipher = "29c3505f571420f6402299b31a02d73a"
        
        if aes.matrix_to_bytes(cipher).hex() == expected_cipher:
            print("Encryption successful")
        else:
            print("Something went wrong")

        plain_text = aes.decrypt(cipher)
        if aes.matrix_to_bytes(plain_text) == b"Two One Nine Two":
            print("Decryption successfull")
        else:
            print("Decryption Failed")
        
AES_Encryption.test()



