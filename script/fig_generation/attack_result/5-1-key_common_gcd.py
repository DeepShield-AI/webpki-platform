
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
from math import gcd, ceil, floor
from time import time
import json

# reference: https://github.com/LaiEthanLai/CS461-MPs/blob/main/Crypto/sol_3.2.4.py
# reference: https://facthacks.cr.yp.to/index.html and https://factorable.net/weakkeys12.extended.pdf

def product(x: list) -> int:
    return x[0]*x[1] if len(x) == 2 else x[0]

def product_tree(x: list) -> list:
    out_lists = [x]
    # print('constructing the product tree')
    s = time()
    while len(x) > 1:
        x = [product(x[2*i:2*(i+1)]) for i in (range(ceil(len(x)/2)))]
        out_lists.append(x)
    print(f'done, takes {time()-s} seconds')
    return out_lists

def remainder_tree(x: list) -> list:
    out_lists = [x[-1][0]]
    # print('constructing the remainder tree')
    s = time()
    for i in range(len(x)-2, -1, -1):
        out_lists = [out_lists[floor(j/2)] % (x[i][j]**2) for j in range(len(x[i]))]
    print(f'done, takes {time()-s} seconds')
    return out_lists

if __name__ == '__main__':
    with open(r'5.txt', 'r', encoding='utf-8') as f:
        json_data = json.load(f)
        for domain, data in json_data.items():
            if len(data) > 10:
                mod_list = list(set(data))
                products = product_tree(mod_list)
                remainders = remainder_tree(products)
                valid_mod = []
                Ps = []

                # print('computing GCDs')
                for idx, i in enumerate(remainders):
                    p = gcd((i // mod_list[idx]), mod_list[idx])
                    if p != 1:
                        Ps += p,
                        valid_mod += mod_list[idx],

                if valid_mod:
                    print(valid_mod)

                # with open(args.cipher, 'r') as f:
                #     ciphertext = f.read()

                # for i in range(len(valid_mod)):

                #     p = Ps[i]
                #     modulus = valid_mod[i]
                #     q = modulus // p
                #     d = inverse(65537, (p-1)*(q-1))
                #     # Construct the RSA key for the computed values
                #     key = RSA.construct((int(modulus), int(65537), int(d)))
                #     try:
                #         plaintext = decrypt(key, ciphertext) 
                #         print(plaintext.decode('ascii'))
                #         with open(args.output, 'w') as out_file:
                #             out_file.write(plaintext.decode('ascii'))
                #             print(f'Written to {args.output}!')
                #     except ValueError:
                #         pass
