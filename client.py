import socket, json, sys, random
from Crypto.Util.number import inverse, getPrime
from Crypto.Random.random import getrandbits
from math import gcd

# Connect to BOTH servers
ctf_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctf_socket.connect(("localhost", 8080))

va_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
va_socket.connect(("localhost", 9090))

# Client generates OWN keypair
p = getPrime(1024)
q = getPrime(1024)
phi = (p-1)*(q-1)
n = p * q
e = random.randint(2, phi-1)
while gcd(e, phi) != 1:
    e = random.randint(2, phi-1)
d = inverse(e, phi)

voterE, voterD, voterN = e, d, n
ctfE = ctfN = None

def blindingfactor(N):
    r = getrandbits(512) % N
    while gcd(r, N) != 1:
        r += 1
    return r

def blind(msg, e, n):
    r = blindingfactor(n)
    return r, (pow(r, e, n) * msg) % n

def unblind(bsm, r, n):
    return (bsm * inverse(r, n)) % n

def print_options():
    print("\n1. Register")
    print("2. Cast Vote")
    print("3. View Results")
    print("4. Exit")

while True:
    print_options()
    choice = int(input())

    if choice == 1:
        # Send OWN public key to CTF server
        payload = json.dumps({
            "choice": "register",
            "voterE": str(voterE),
            "voterN": str(voterN)
        })
        ctf_socket.sendall(payload.encode())

        recv = ctf_socket.recv(4096).decode()
        if "registered" in recv.lower() and "already" in recv.lower():
            print(recv)
            continue

        data = json.loads(recv)
        ctfE = int(data["ctfE"])
        ctfN = int(data["ctfN"])
        print("Registered! Got CTF public key.")

    elif choice == 2:
        print("Enter candidate id (1-10):")
        vote = int(input())

        # Step 1: Blind under CTF's public key
        r, blindedVote = blind(vote, ctfE, ctfN)

        # Step 2: Sign blinded vote with OWN private key (authentication)
        authSig = pow(blindedVote, voterD, voterN)

        # Step 3: Send to CTF server for blind signing
        payload = json.dumps({
            "choice": "blindsign",
            "blindedVote": str(blindedVote),
            "authSig": str(authSig),
            "e": str(voterE),
            "N": str(voterN)
        })
        ctf_socket.sendall(payload.encode())

        recv = ctf_socket.recv(4096).decode()
        if "{" not in recv:
            print(recv)
            continue

        data = json.loads(recv)
        signedBlind = int(data["signedBlind"])

        # Step 4: Unblind
        unblindedSig = unblind(signedBlind, r, ctfN)

        # Step 5: Verify locally
        check = pow(unblindedSig, ctfE, ctfN)
        if check != vote:
            print("Local verification failed!")
            continue

        print("CTF signature verified locally.")

        # Step 6: Send to Verification Authority — NO voter identity attached
        payload = json.dumps({
            "choice": "cast",
            "vote": str(vote),
            "unblindedSig": str(unblindedSig)
        })
        va_socket.sendall(payload.encode())

        recv = va_socket.recv(4096).decode()
        print(recv)

    elif choice == 3:
        payload = json.dumps({"choice": "results"})
        va_socket.sendall(payload.encode())
        print(va_socket.recv(4096).decode())

    elif choice == 4:
        ctf_socket.send(b"disconnect")
        va_socket.send(b"disconnect")
        ctf_socket.close()
        va_socket.close()
        sys.exit()
