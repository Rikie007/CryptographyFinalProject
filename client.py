import socket, json, sys, random, uuid, hashlib
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

def get_menu_choice():
    """Get valid menu choice from user with error handling"""
    while True:
        try:
            print_options()
            choice = int(input("Enter your choice: "))
            if choice not in [1, 2, 3, 4]:
                print(f"Error: Invalid choice '{choice}'. Please enter 1, 2, 3, or 4.")
                continue
            return choice
        except ValueError:
            print("Error: Please enter a valid number (1, 2, 3, or 4).")
            continue

while True:
    choice = get_menu_choice()

    if choice == 1:
        # Send OWN public key to CTF server
        try:
            payload = json.dumps({
                "choice": "register",
                "voterE": str(voterE),
                "voterN": str(voterN)
            })
            ctf_socket.sendall(payload.encode())

            recv = ctf_socket.recv(4096).decode()
            if "registered" in recv.lower() and "already" in recv.lower():
                print(f" {recv}")
                continue

            data = json.loads(recv)
            ctfE = int(data["ctfE"])
            ctfN = int(data["ctfN"])
            print("Registered! Got CTF public key.")
        except json.JSONDecodeError as e:
            print(f" Error parsing server response: {str(e)}")
            continue
        except Exception as e:
            print(f" Registration error: {str(e)}")
            continue

    elif choice == 2:
        while True:
            try:
                vote = int(input("Enter candidate id (1-10): "))
                if not (1 <= vote <= 10):
                    print(f" Error: Candidate id must be between 1 and 10. You entered: {vote}")
                    continue
                break
            except ValueError:
                print(" Error: Please enter a valid number between 1 and 10.")
                continue

        # Step 0: Generate unique nonce for this vote (REPLAY ATTACK PROTECTION)
        nonce = str(uuid.uuid4())
        
        # Create combined message: vote:nonce (for replay protection)
        combined_msg = f"{vote}:{nonce}"
        msg_hash = int(hashlib.sha256(combined_msg.encode()).hexdigest(), 16)

        # Step 1: Blind under CTF's public key
        try:
            r, blindedVote = blind(msg_hash, ctfE, ctfN)

            # Step 2: Sign blinded vote with OWN private key (authentication)
            # Hash blindedVote to match server's updated secure verification
            blinded_hash = int(hashlib.sha256(str(blindedVote).encode()).hexdigest(), 16)
            authSig = pow(blinded_hash, voterD, voterN)

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
            if check != msg_hash:
                print("Local verification failed!")
                continue

            print("CTF signature verified locally.")

            # Step 6: Send to Verification Authority — NO voter identity attached
            payload = json.dumps({
                "choice": "cast",
                "vote": str(vote),
                "nonce": nonce,
                "unblindedSig": str(unblindedSig)
            })
            va_socket.sendall(payload.encode())

            recv = va_socket.recv(4096).decode()
            print(recv)
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            print(f" Error casting vote: {str(e)}")
            continue
        except Exception as e:
            print(f" Unexpected error: {str(e)}")
            continue

    elif choice == 3:
        try:
            payload = json.dumps({"choice": "results"})
            va_socket.sendall(payload.encode())
            results = va_socket.recv(4096).decode()
            print("Current Results:")
            print(results)
        except Exception as e:
            print(f" Error fetching results: {str(e)}")
            continue

    elif choice == 4:
        try:
            ctf_socket.send(b"disconnect")
            va_socket.send(b"disconnect")
            ctf_socket.close()
            va_socket.close()
            print("Goodbye!")
            sys.exit()
        except Exception as e:
            print(f"  Error during exit: {str(e)}")
            sys.exit()