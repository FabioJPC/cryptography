import secrets

PRIME_BIT_SIZE = 1024


def generate_prime_candidate(bits):
    flag = False
    while flag != True:
        p = secrets.randbits(bits)
        # Add 1 as the last bit to guarantee an odd number
        p = p|1
        flag = is_low_level_prime(p)
    return p
    

def miller_rabin(n, k = 40):

    # Discard clearly non prime numbers, or True un case of 2
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 : return False

    # GENERAL RULES FOR PRIME NUMBERS
    # For a given odd integer n > 2, let's write
    # n - 1 as (2^s)d
    # Consider a interger a, called base which is a coprime to n
    # Number is a potential prime if a^d mod(n) = 1 or n-1

    # Initial d as stated in the algorithm rule
    d = n - 1

    # Number of steps to test in the quadratic ladder
    s = 0

    # Find the powers of 2 from n=1 : (2^s)*d
    while d % 2 == 0:
        d //= 2
        s += 1

    # Execute the test k times, with random values for a
    for _ in range(k):
        a = secrets.randbelow(n - 2) + 2

        # Return the Modular Exponentiation
        x = pow(a, d, n)

        #Step One (x == 1) is good here
        if x == 1 or x == n -1:
            # Continue for the next test
            continue

        # Step Two (x == 1) is not good here, means an imposter, must return False
        # Run quadratic ladder
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            # If x never found to be n-, means imposter
            return False
        
    # If all tests are good is a prime number
    return True

def is_low_level_prime(n):
    small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for prime in small_primes:
        if n % prime == 0:
            return False
    return True

def generate_p_and_q():
    # Generate 1st prime number p
    p = generate_prime_candidate(PRIME_BIT_SIZE)
    while not miller_rabin(p):
        p = generate_prime_candidate(PRIME_BIT_SIZE)

    # Generate 2nd prime number q, and guarantee it's different than p
    q = generate_prime_candidate(PRIME_BIT_SIZE)
    while not miller_rabin(q) or q == p:
        q = generate_prime_candidate(PRIME_BIT_SIZE)

    return p, q

def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        r = a % b
        a, b = b, r

        new_x1 = x0 - q * x1
        x0, x1 = x1, new_x1

        new_y1 = y0 - q * y1
        y0, y1 = y1, new_y1

    return a, x0, y0

def generate_keys():
    e = 65537

    while True:
        p, q = generate_p_and_q()
        phi = (p-1) * (q-1)
        g, x, y = extended_gcd(e, phi)
        if g == 1:
            break

    n = p * q
    d = x % phi

    return (e, n), (d, n)



# Start o RSA public and private key generation
public, private = generate_keys()
e = public[0]
n = public[1]
d = private[0]

message = 123456789

ciphertext = pow(message, e, n)
print("CIPHER: ", ciphertext)

decipher = pow(ciphertext, d , n)
print("\n\nDECIPHER: ", decipher)

