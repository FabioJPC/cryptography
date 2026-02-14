import os

#Import the base tables for blowfish start
from blowfish_base_tables import p_array, s0, s1, s2, s3

def pad(data):
	pad_len = 8 - (len(data) % 8)
	return data + bytes([pad_len] * pad_len)

def unpad(data):
	pad_len = data[-1]
	return data[:-pad_len]

def get_input():
	text = input("Plase insert the text you want to cryptograph: ").encode()

	key = input("Please insert a password to encode and decode tou text later: ").encode()

	while len(key) < 4 or len(key) > 56:
		key = input("The password must be minimum 4 letters and maximum of 56, try again:\n").encode()
	
	return key, text


def build_parray(key):
	p = p_array.copy()
	k_index = 0
	for i in range(18):
		data = 0x00000000
		for k in range(4):
			data = (data << 8) | key[k_index]
			k_index = (k_index + 1) % len(key)
		p[i] ^= data
	return p
	

def f(x):
	a = (x >> 24) & 0xFF
	b = (x >> 16) & 0xFF
	c = (x >> 8) & 0xFF
	d = x & 0xFF

	y = (s[0][a] + s[1][b]) & 0xFFFFFFFF
	y = y ^ s[2][c]
	y = (y + s[3][d]) & 0xFFFFFFFF

	return y

def encrypt_block(L, R, p_array):
	for i in range(16):
		L ^= p_array[i]
		R ^= f(L)
		L, R = R, L

	L, R = R, L
	R ^= p_array[16]
	L ^= p_array[17]
	return L & 0xFFFFFFFF, R & 0xFFFFFFFF

def decrypt_block(L, R, p_array):
	for i in range(17,1,-1):
		L ^= p_array[i]
		R ^= f(L)
		L, R = R, L
	
	L, R = R, L
	R ^= p_array[1]
	L ^= p_array[0]
	return L & 0xFFFFFFFF, R & 0xFFFFFFFF


def expand_key(key):
	global s

	s = [s0.copy(), s1.copy(), s2.copy(), s3.copy()]

	p = build_parray(key)

	L = 0x00000000
	R = 0x00000000

	#Update P array
	for i in range(0,18,2):
		L, R = encrypt_block(L, R, p)
		p[i] = L
		p[i+1] = R

	#Update S boxes
	for box in range(4):
		for i in range(0, 256, 2):
			L, R = encrypt_block(L, R, p)
			s[box][i] = L
			s[box][i+1] = R
	return p

# ECB Crypto start

def encrypt_ecb(data, p_array):
	data = pad(data)
	ciphertext = b""

	for i in range(0, len(data), 8):
		block = data[i: i+8]
		L = int.from_bytes(block[:4], "big")
		R = int.from_bytes(block[4:], "big")

		L, R = encrypt_block(L, R, p_array)

		ciphertext += L.to_bytes(4, "big")
		ciphertext += R.to_bytes(4, "big")
	return ciphertext

def decrypt_ecb(data, p_array):
	plaintext = b""

	for i in range(0, len(data), 8):
		block = data[i: i+8]
		L = int.from_bytes(block[:4], "big")
		R = int.from_bytes(block[4:], "big")

		L, R = decrypt_block(L, R, p_array)

		plaintext += L.to_bytes(4, "big")
		plaintext += R.to_bytes(4, "big")
	
	print(plaintext)

	return unpad(plaintext)

#ECB Crypto end

#CBC Crypto start

def encrypt_cbc(data, p_array):
	data = pad(data)
	iv = os.urandom(8)
	ciphertext = iv
	prev_block = iv

	for i in range(0, len(data), 8):
		block = data[i:i+8]
		xored = bytes(a ^ b for a, b in zip(block, prev_block))

		L = int.from_bytes(xored[:4], "big")
		R = int.from_bytes(xored[4:], "big")

		L, R =  encrypt_block(L, R, p_array)

		encrypted_block = L.to_bytes(4, "big") + R.to_bytes(4, "big")
		ciphertext += encrypted_block
		prev_block = encrypted_block

	return ciphertext

def _decrypt_cbc_raw(ciphertext, p_array, iv):

    plaintext = b""
    prev_block = iv

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]

        L = int.from_bytes(block[:4], "big")
        R = int.from_bytes(block[4:], "big")

        L, R = decrypt_block(L, R, p_array)

        decrypted_block = L.to_bytes(4, "big") + R.to_bytes(4, "big")

        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))

        plaintext += plain_block
        prev_block = block

    return plaintext

def decrypt_cbc(data, p_array):
	iv = data[:8]
	ciphertext = data[8:]
	plaintext = _decrypt_cbc_raw(ciphertext, p_array, iv)
	return unpad(plaintext)

#CBC Crypto end

#Testing
#CBC Encryption Unit Test
def run_test():

	print("Running unit test")
	key = bytes.fromhex("0123456789ABCDEFF0E1D2C3B4A59687")
	iv = bytes.fromhex("FEDCBA9876543210")
	plaintext = bytes.fromhex("37363534333231204E6F772069732074")
	expected_cipher = bytes.fromhex("6B77B4D63006DEE605B156E274039793")

	p_final = expand_key(key)
	cipher = test_encrypt_cbc(plaintext, p_final, iv)
	cipher_without_iv = cipher[8:]

	if expected_cipher != cipher_without_iv:
		print("Test failed in encryption mode")
	else:
		expected_decrypt = _decrypt_cbc_raw(cipher_without_iv, p_final, iv)

		if expected_decrypt == plaintext:
			print("Test OK")
		else:
			print("Test failed in decryption mode")


def test_encrypt_cbc(data, p_array, temp_iv):

	iv = temp_iv #os.urandom(8)
	ciphertext = iv
	prev_block = iv

	for i in range(0, len(data), 8):
		block = data[i:i+8]
		xored = bytes(a ^ b for a, b in zip(block, prev_block))

		L = int.from_bytes(xored[:4], "big")
		R = int.from_bytes(xored[4:], "big")

		L, R =  encrypt_block(L, R, p_array)

		encrypted_block = L.to_bytes(4, "big") + R.to_bytes(4, "big")
		ciphertext += encrypted_block
		prev_block = encrypted_block

	return ciphertext

run_test()

key, text = get_input()
p_final = expand_key(key)
cipher = encrypt_cbc(text, p_final)
dec = decrypt_cbc(cipher, p_final)

print("Original:", text.decode())
print("Encrypted:", cipher.hex())
print("Decrypted:", dec.decode())
