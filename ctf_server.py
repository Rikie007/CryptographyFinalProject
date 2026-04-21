import socket, json, random, sys, _thread
from Crypto.Util.number import inverse, getPrime
from math import gcd

publicKeys = []
voted = {}

# CTF keypair
ctf_p = getPrime(1024)
ctf_q = getPrime(1024)
ctf_phi = (ctf_p - 1) * (ctf_q - 1)
ctf_n = ctf_p * ctf_q

ctf_e = random.randint(2, ctf_phi - 1)
while gcd(ctf_e, ctf_phi) != 1:
    ctf_e = random.randint(2, ctf_phi - 1)

ctf_d = inverse(ctf_e, ctf_phi)

# Share ctf public key with verification authority (in real system, published publicly)
with open("ctf_public.json", "w") as f:
    json.dump({"ctfE": str(ctf_e), "ctfN": str(ctf_n)}, f)

print("CTF public key saved for Verification Authority")

def logic(conn, addr):
    while True:
        output = conn.recv(4096)
        data = output.strip().decode()

        if data == "disconnect":
            conn.close()
            return

        try:
            data = json.loads(data)

            if data["choice"] == "register":
                voterE = int(data["voterE"])
                voterN = int(data["voterN"])

                if (voterE, voterN) in publicKeys:
                    conn.sendall(b"Already registered!")
                    continue

                publicKeys.append((voterE, voterN))

                payload = json.dumps({
                    "ctfE": str(ctf_e),
                    "ctfN": str(ctf_n)
                })
                conn.sendall(payload.encode())
                print(f"Voter registered: (e={voterE})")

            elif data["choice"] == "blindsign":
                blindedVote = int(data["blindedVote"])
                authSig     = int(data["authSig"])
                voterE      = int(data["e"])
                voterN      = int(data["N"])

                # Check voter is registered
                if (voterE, voterN) not in publicKeys:
                    conn.sendall(b"Voter not registered!")
                    continue

                # Check not already signed for this voter
                if (voterE, voterN) in voted:
                    conn.sendall(b"Already signed for this voter!")
                    continue

                # ✅ Verify voter authentication
                verified = pow(authSig, voterE, voterN)
                if verified != blindedVote:
                    conn.sendall(b"Authentication failed!")
                    continue

                # ✅ Sign with CTF private key — server never sees actual vote
                signedBlind = pow(blindedVote, ctf_d, ctf_n)

                voted[(voterE, voterN)] = True   # prevent double signing

                payload = json.dumps({"signedBlind": str(signedBlind)})
                conn.sendall(payload.encode())
                print("Blind signed for voter. CTF does NOT know the actual vote.")

        except Exception as ex:
            print(ex)
            conn.close()
            return

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('localhost', 8080))
server_socket.listen(5)
print("CTF Server listening on port 8080...")

try:
    while True:
        try:
            server_socket.settimeout(1)
            conn, addr = server_socket.accept()
            _thread.start_new_thread(logic, (conn, addr))
        except socket.timeout:
            continue
except KeyboardInterrupt:
    print("Shutting down CTF server...")
finally:
    server_socket.close()