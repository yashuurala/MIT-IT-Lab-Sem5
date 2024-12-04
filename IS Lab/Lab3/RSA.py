import random
import math

prime = set()

public_key = None
private_key = None
n = None


def primefiller():
    seive = [True] * 250
    seive[0] = False
    seive[1] = False
    for i in range(2, 250):
        if seive[i]:
            for j in range(i * 2, 250, i):
                seive[j] = False

    for i in range(len(seive)):
        if seive[i]:
            prime.add(i)


def pickrandomprime():
    global prime
    k = random.randint(0, len(prime) - 1)
    it = iter(prime)
    for _ in range(k):
        next(it)

    ret = next(it)
    prime.remove(ret)
    return ret


def setkeys():
    global public_key, private_key, n
    prime1 = pickrandomprime()  # First prime number
    prime2 = pickrandomprime()  # Second prime number

    n = prime1 * prime2
    fi = (prime1 - 1) * (prime2 - 1)

    e = 2
    while True:
        if math.gcd(e, fi) == 1:
            break
        e += 1

    public_key = (n, e)

    d = 2
    while True:
        if (d * e) % fi == 1:
            break
        d += 1

    private_key = (n, d)


def modular_exponentiation(base, exponent, mod):
    result = 1
    base = base % mod
    while exponent > 0:
        if (exponent % 2) == 1:
            result = (result * base) % mod
        exponent = exponent >> 1
        base = (base * base) % mod
    return result


def encrypt(message):
    global public_key
    n, e = public_key
    encrypted_text = []
    for letter in message:
        encrypted_char = modular_exponentiation(ord(letter), e, n)
        encrypted_text.append(encrypted_char)
    return encrypted_text


def decrypt(encrypted_text):
    global private_key
    n, d = private_key
    decrypted = ''
    for num in encrypted_text:
        decrypted_char = modular_exponentiation(num, d, n)
        decrypted += chr(decrypted_char)
    return decrypted


def main():
    primefiller()
    setkeys()

    message = input("Enter the message: ")
    coded = encrypt(message)

    print("\n\nThe encoded message (encrypted by public key):")
    print(' '.join(str(p) for p in coded))

    decoded_message = decrypt(coded)
    print("\n\nThe decoded message (decrypted by private key):")
    print(decoded_message)


if __name__ == "__main__":
    main()
