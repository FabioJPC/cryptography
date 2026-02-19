import aes_base_tables

class AES_Encryption:
    def __init__(self, key):

        # Initialize base vectors
        self.s_box = aes_base_tables.base_sbox.copy()
        self.rcon = aes_base_tables.base_rcon.copy()
        self.galois2 = aes_base_tables.galois2.copy()
        self.galois3 = aes_base_tables.galois3.copy()
        self.galois9 = aes_base_tables.galois9.copy()
        self.galois11 = aes_base_tables.galois11.copy()
        self.galois13 = aes_base_tables.galois13.copy()
        self.galois14 = aes_base_tables.galois14.copy()

        # Key expansion
        self.round_keys = self._key_expansion(bytearray(key))

        # Generate inverse s-box
        self.inv_box = bytearray(256)
        for i in range(256):
            sbox_value = self.s_box[i]
            self.inv_box[sbox_value] = i

    
    #Helpers
    def _rot_word(self, word):
        return word[1:] + word[:1]
    
    def _sub_word(self, word):
        new_word = []
        for b in word:
            new_word.append(self.s_box[b])
        return bytearray(new_word)

    def _xor_words(self, w1, w2):
        return bytearray(a ^ b for a, b in zip(w1, w2))

    def _xtime(self, b):
        if b & 0x80:
            return ((b << 1) ^ 0x1b) & 0xFF
        return (b << 1) & 0xFF
    
    def _pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]
    
    # Bytes substitution and inverse version
    def _sub_bytes(self, state, s_box):
        for i in range(16):
            state[i] = s_box[state[i]]
        return state
    
    def _inv_sub_bytes(self, state, inv_s_box):
        for i in range(16):
            state[i] = inv_s_box[state[i]]
        return state

    # Shiftrows and inverse version
    def _shiftrows(self, s):
        #row 1
        s[1] , s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        #row 2
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        #row 3
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        return s

    def _inv_shiftrows(self, s):
        #row 1
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        #row 2
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        #row 3
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
        return s

    # MixColumns step and inverse
    def _mix_columns(self, state):
        for i in range(4):
            base = i * 4

            a0 = state[base]
            a1 = state[base + 1]
            a2 = state[base + 2]
            a3 = state[base + 3]

            state[base] = self._xtime(a0) ^ (self._xtime(a1) ^ a1) ^ a2 ^ a3
            state[base + 1] = a0 ^ self._xtime(a1) ^ (self._xtime(a2) ^ a2) ^ a3
            state[base + 2] = a0 ^ a1 ^ self._xtime(a2) ^ (self._xtime(a3) ^ a3)
            state[base + 3] = (self._xtime(a0) ^ a0) ^ a1 ^ a2 ^ self._xtime(a3)
        return state

    def _inv_mix_columns(self, state):
        for i in range(4):
            base = i * 4
            a0 = state[base]
            a1 = state[base + 1]
            a2 = state[base + 2]
            a3 = state[base + 3]

            state[base]     = self.galois14[a0] ^ self.galois11[a1] ^ self.galois13[a2] ^ self.galois9[a3]
            state[base + 1] = self.galois9[a0]  ^ self.galois14[a1] ^ self.galois11[a2] ^ self.galois13[a3]
            state[base + 2] = self.galois13[a0] ^ self.galois9[a1]  ^ self.galois14[a2] ^ self.galois11[a3]
            state[base + 3] = self.galois11[a0] ^ self.galois13[a1] ^ self.galois9[a2]  ^ self.galois14[a3]
        return state

    def _add_round_key(self, state, key):
        for i in range(16):
            state[i] ^= key[i]
        return state

     #Key expansion
    
    def _key_expansion(self, key):
        words= []

        for i in range(4):
            word = key[i*4 : (i+1) *4 ]
            words.append(bytearray(word))
            
        for i in range(4,44):
            temp = words[i-1].copy()

            if i % 4 == 0:
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                temp[0] ^= self.rcon[(i // 4) - 1]

            new_word = self._xor_words(words[i-4], temp)
            words.append(new_word)

        round_keys = []
        for i in range(0, 44, 4):
            rk = bytearray()
            for j in range(4):
                rk.extend(words[i + j])
            round_keys.append(rk)
                
        return round_keys

    def _split_blocks(self, data):
        blocks = []
        for i in range(0, len(data), 16):
            blocks.append(data[i:i+16])
        return blocks

    def encrypt_ecb(self, data):
        state = self._pad(data)
        blocks = self._split_blocks(state)

        result = bytearray()

        for block in blocks:
            encrypted = self.encrypt(block)
            result.extend(encrypted)
        return result
    
    def decrypt_ecb(self, data):
        blocks = self._split_blocks(data)
        result = bytearray()

        for block in  blocks:
            decrypted = self.decrypt(block)
            result.extend(decrypted)
        result = self._unpad(result)
        return bytes(result)

    # ENCRYPTION CALL
    def encrypt(self, plain_text_bytes):
        state = bytearray(plain_text_bytes)
    
        # Step 0
        state = self._add_round_key(state, self.round_keys[0])

        # Step 1 - 10
        for r in range(1, 10):
            state = self._sub_bytes(state, self.s_box)
            state = self._shiftrows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[r])

        # Step 11
        state = self._sub_bytes(state, self.s_box)
        state = self._shiftrows(state)
        state = self._add_round_key(state, self.round_keys[10])
        return state

    #DECRYPTION CALL
    def decrypt(self, cipher_text):
        state = bytearray(cipher_text)

        state = self._add_round_key(state, self.round_keys[10])

        for r in range(9, 0, -1):
            state = self._inv_shiftrows(state)
            state = self._inv_sub_bytes(state, self.inv_box)

            state = self._add_round_key(state, self.round_keys[r])
            state = self._inv_mix_columns(state) 

        state = self._inv_shiftrows(state)
        state = self._inv_sub_bytes(state, self.inv_box)

        state = self._add_round_key(state, self.round_keys[0])
        return state
    
    def test():
        aes = AES_Encryption(b"Thats my Kung Fu")
        plain_text = b"Two One Nine Two"
        expected_cipher = "29c3505f571420f6402299b31a02d73a"

        cipher = aes.encrypt(plain_text)
        decipher = aes.decrypt(cipher)

        if cipher.hex() == expected_cipher:
            print("Encryption successfull")

            if decipher == plain_text:
                print("Decryption successfull")
            else:
                print("Decryption failed")
        else:
            print("Encription Failed")


#AES_Encryption.test()

def teste2():
    aes = AES_Encryption(b"Thats my Kung Fu")

    text = b"Esse texto tem mais de 16 bytes!!"

    cipher = aes.encrypt_ecb(text)
    decrypted = aes.decrypt_ecb(cipher)

    print("Original :", text)
    print("Decrypted:", decrypted)

teste2()




