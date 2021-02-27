import numpy as np

from keygen import keygen
from crypt import encrypt, decrypt

from operations import add_plain, mul_plain


def main():
    # Scheme's parameters
    # polynomial modulus degree
    n = 2**4
    # ciphertext modulus
    q = 2**15
    # plaintext modulus
    t = 2**8
    # polynomial modulus
    poly_mod = np.array([1] + [0] * (n - 1) + [1])
    # Keygen
    pk, sk = keygen(n, q, poly_mod)
    # Encryption
    pt1, pt2 = 73, 20
    ct1 = encrypt(pk, n, q, t, poly_mod, pt1)
    ct2 = encrypt(pk, n, q, t, poly_mod, pt2)

    print("[+] Ciphertext ct1({}):".format(pt1))
    print("")
    print("\t ct1_0:", ct1[0])
    print("\t ct1_1:", ct1[1])
    print("")
    print("[+] Ciphertext ct2({}):".format(pt2))
    print("")
    print("\t ct1_0:", ct2[0])
    print("\t ct1_1:", ct2[1])
    print("")
    
    # Evaluation
    cst1, cst2 = 7, 5
    # 73 + 7
    ct3 = add_plain(ct1, cst1, q, t, poly_mod)
    # 20 * 5
    ct4 = mul_plain(ct2, cst2, q, t, poly_mod)

    # Decryption
    decrypted_ct3 = decrypt(sk, n, q, t, poly_mod, ct3)
    decrypted_ct4 = decrypt(sk, n, q, t, poly_mod, ct4)

    print("[+] Decrypted ct3(ct1 + {}): {}".format(cst1, decrypted_ct3))
    print("[+] Decrypted ct4(ct2 * {}): {}".format(cst2, decrypted_ct4))

    assert(decrypted_ct3 == pt1 + cst1)
    assert(decrypted_ct4 == pt2 * cst2)

if __name__ == "__main__":
    main()
