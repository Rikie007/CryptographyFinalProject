import socket, json, _thread

votesTally = {}

# Load CTF public key (published by CTF server)
with open("ctf_public.json", "r") as f:
    ctf_data = json.load(f)

ctf_e = int(ctf_data["ctfE"])
ctf_n = int(ctf_data["ctfN"])
print("Verification Authority loaded CTF public key")

def logic(conn, addr):
    while True:
        output = conn.recv(4096)
        data = output.strip().decode()

        if data == "disconnect":
            conn.close()
            return

        try:
            data = json.loads(data)

            if data["choice"] == "cast":
                vote_val      = int(data["vote"])
                unblindedSig  = int(data["unblindedSig"])

                # ✅ Check CTF actually signed this vote
                verified = pow(unblindedSig, ctf_e, ctf_n)
                if verified != vote_val:
                    conn.sendall(b"Invalid! CTF did not sign this vote.")
                    continue

                if 1 <= vote_val <= 10:
                    votesTally[vote_val] = votesTally.get(vote_val, 0) + 1
                    conn.sendall(b"Vote counted successfully!")
                    print(f"Vote counted: Candidate {vote_val}")
                else:
                    conn.sendall(b"Invalid vote value!")

            elif data["choice"] == "results":
                conn.sendall(json.dumps(votesTally).encode())

        except Exception as ex:
            print(ex)
            conn.close()
            return

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('localhost', 9090))   # different port!
server_socket.listen(5)
print("Verification Authority listening on port 9090...")

try:
    while True:
        try:
            server_socket.settimeout(1)
            conn, addr = server_socket.accept()
            _thread.start_new_thread(logic, (conn, addr))
        except socket.timeout:
            continue
except KeyboardInterrupt:
    print("Shutting down Verification Authority...")
finally:
    server_socket.close()