"""
Secure Blind Signature E-Voting System — Flask Web Frontend
Replaces the terminal client.py with a full web interface.
All cryptographic operations are preserved exactly from client.py.
"""

import socket, json, uuid, hashlib, random
from math import gcd
from Crypto.Util.number import inverse, getPrime
from Crypto.Random.random import getrandbits
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = "evoting-secret-key-change-in-prod"

CTF_HOST, CTF_PORT = "localhost", 8080
VA_HOST,  VA_PORT  = "localhost", 9090

# ─── Crypto helpers (identical to client.py) ────────────────────────────────

def generate_rsa_keypair():
    p = getPrime(1024)
    q = getPrime(1024)
    phi = (p - 1) * (q - 1)
    n = p * q
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = inverse(e, phi)
    return int(e), int(d), int(n)

def blinding_factor(N):
    r = getrandbits(512) % N
    while gcd(r, N) != 1:
        r += 1
    return r

def blind(msg, e, n):
    r = blinding_factor(n)
    return r, (pow(r, e, n) * msg) % n

def unblind(bsm, r, n):
    return (bsm * inverse(r, n)) % n

# ─── Socket helpers ──────────────────────────────────────────────────────────

def ctf_send(payload: dict) -> bytes:
    """Open a fresh socket to CTF server, send payload, return raw response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((CTF_HOST, CTF_PORT))
    s.sendall(json.dumps(payload).encode())
    data = s.recv(4096)
    s.close()
    return data

def va_send(payload: dict) -> bytes:
    """Open a fresh socket to Verification Authority, send payload, return raw response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((VA_HOST, VA_PORT))
    s.sendall(json.dumps(payload).encode())
    data = s.recv(4096)
    s.close()
    return data

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register-page")
def register_page():
    return render_template("register.html")

@app.route("/vote-page")
def vote_page():
    return render_template("vote.html")

@app.route("/results-page")
def results_page():
    return render_template("results.html")

@app.route("/about")
def about():
    return render_template("about.html")

# ─── API endpoints ────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    """
    1. Generate fresh RSA keypair for this voter session.
    2. Send public key to CTF server.
    3. Receive CTF's public key back.
    4. Store everything in session.
    """
    try:
        e, d, n = generate_rsa_keypair()

        raw = ctf_send({"choice": "register", "voterE": str(e), "voterN": str(n)})
        text = raw.decode()

        if "already" in text.lower():
            return jsonify({"success": False, "message": "This key is already registered."})

        ctf_data = json.loads(text)
        ctf_e = int(ctf_data["ctfE"])
        ctf_n = int(ctf_data["ctfN"])

        # Persist voter keys + CTF public key in session
        session["voterE"] = str(e)
        session["voterD"] = str(d)
        session["voterN"] = str(n)
        session["ctfE"]   = str(ctf_e)
        session["ctfN"]   = str(ctf_n)
        session["voted"]  = False

        return jsonify({
            "success": True,
            "message": "Registered successfully!",
            "voterE": str(e),
            "voterN": str(n),
            "ctfE":   str(ctf_e),
            "ctfN":   str(ctf_n),
        })

    except ConnectionRefusedError:
        return jsonify({"success": False, "message": "CTF Server is offline. Start ctf_server.py first."})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)})


@app.route("/api/vote", methods=["POST"])
def api_vote():
    """
    Full blind-signature voting flow (mirrors client.py step-by-step):
      0. Validate session / not-already-voted.
      1. Get vote + generate nonce.
      2. Hash(vote:nonce).
      3. Blind under CTF public key.
      4. Sign blinded message with voter private key (authentication).
      5. Send to CTF for blind signing.
      6. Unblind CTF's signature.
      7. Local verification.
      8. Send anonymous vote + nonce + sig to Verification Authority.
    """
    try:
        body = request.get_json()
        vote = int(body.get("vote", 0))
        if not (1 <= vote <= 10):
            return jsonify({"success": False, "message": "Invalid candidate (1-10)."})

        if not all(k in session for k in ("voterE", "voterD", "voterN", "ctfE", "ctfN")):
            return jsonify({"success": False, "message": "Not registered. Please register first."})

        if session.get("voted"):
            return jsonify({"success": False, "message": "You have already voted in this session."})

        voter_e = int(session["voterE"])
        voter_d = int(session["voterD"])
        voter_n = int(session["voterN"])
        ctf_e   = int(session["ctfE"])
        ctf_n   = int(session["ctfN"])

        # Step 1 — nonce + combined message
        nonce        = str(uuid.uuid4())
        combined_msg = f"{vote}:{nonce}"
        msg_hash     = int(hashlib.sha256(combined_msg.encode()).hexdigest(), 16)

        # Step 2 — blind
        r, blinded_vote = blind(msg_hash, ctf_e, ctf_n)

        # Step 3 — sign blinded vote with voter private key (authentication token)
        auth_sig = pow(blinded_vote, voter_d, voter_n)

        # Step 4 — send to CTF for blind signing
        raw = ctf_send({
            "choice":      "blindsign",
            "blindedVote": str(blinded_vote),
            "authSig":     str(auth_sig),
            "e":           str(voter_e),
            "N":           str(voter_n),
        })
        text = raw.decode()

        if "{" not in text:
            return jsonify({"success": False, "message": f"CTF error: {text}"})

        signed_blind = int(json.loads(text)["signedBlind"])

        # Step 5 — unblind
        unblinded_sig = unblind(signed_blind, r, ctf_n)

        # Step 6 — local verify
        if pow(unblinded_sig, ctf_e, ctf_n) != msg_hash:
            return jsonify({"success": False, "message": "Local signature verification failed!"})

        # Step 7 — cast anonymously to Verification Authority
        raw2 = va_send({
            "choice":      "cast",
            "vote":        str(vote),
            "nonce":       nonce,
            "unblindedSig": str(unblinded_sig),
        })

        va_response = raw2.decode()
        if "counted" in va_response.lower():
            session["voted"] = True
            return jsonify({"success": True, "message": "Your vote was cast anonymously and counted!", "candidate": vote})
        else:
            return jsonify({"success": False, "message": f"VA response: {va_response}"})

    except ConnectionRefusedError as ex:
        svc = "CTF Server" if "8080" in str(ex) else "Verification Authority"
        return jsonify({"success": False, "message": f"{svc} is offline."})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)})


@app.route("/api/results", methods=["GET"])
def api_results():
    """Fetch live tally from Verification Authority."""
    try:
        raw = va_send({"choice": "results"})
        tally = json.loads(raw.decode())
        # Ensure all 10 candidates are present
        results = {str(i): tally.get(str(i), tally.get(i, 0)) for i in range(1, 11)}
        return jsonify({"success": True, "results": results})
    except ConnectionRefusedError:
        return jsonify({"success": False, "message": "Verification Authority is offline."})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)})


@app.route("/api/status", methods=["GET"])
def api_status():
    """Return current session state for the frontend."""
    return jsonify({
        "registered": all(k in session for k in ("voterE", "ctfE")),
        "voted":      session.get("voted", False),
        "voterE":     session.get("voterE", ""),
        "voterN":     session.get("voterN", ""),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
