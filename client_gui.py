import socket
import json
import random
import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Util.number import inverse, getPrime
from Crypto.Random.random import getrandbits
from math import gcd

# establish connection with both servers (CTF and Verification Authority)
ctf_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctf_socket.connect(("localhost", 8080))

va_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
va_socket.connect(("localhost", 9090))

# generate RSA key pair for the voter (client side)
p = getPrime(1024)
q = getPrime(1024)
phi = (p-1)*(q-1)
n = p * q

# pick a random e such that gcd(e, phi) = 1
e = random.randint(2, phi-1)
while gcd(e, phi) != 1:
    e = random.randint(2, phi-1)

# compute private key
d = inverse(e, phi)

voterE, voterD, voterN = e, d, n
ctfE = ctfN = None


# generate a random blinding factor r such that gcd(r, N) = 1
def blindingfactor(N):
    r = getrandbits(512) % N
    while gcd(r, N) != 1:
        r += 1
    return r


# blind the message using RSA blinding
def blind(msg, e, n):
    r = blindingfactor(n)
    return r, (pow(r, e, n) * msg) % n


# remove the blinding factor from signed message
def unblind(bsm, r, n):
    return (bsm * inverse(r, n)) % n


def register_voter():
    """Handles voter registration with CTF server"""
    try:
        payload = json.dumps({
            "choice": "register",
            "voterE": str(voterE),
            "voterN": str(voterN)
        })
        ctf_socket.sendall(payload.encode())

        recv = ctf_socket.recv(4096).decode()
        
        # if already registered, just inform user
        if "already" in recv.lower():
            messagebox.showinfo("Info", recv)
            return
        
        # extract CTF public key from response
        data = json.loads(recv)
        global ctfE, ctfN
        ctfE = int(data["ctfE"])
        ctfN = int(data["ctfN"])
        
        messagebox.showinfo("Success", "✓ Registered! Got CTF public key.")
        
    except json.JSONDecodeError as e:
        messagebox.showerror("Error", f"Failed to parse server response: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed: {str(e)}")


def cast_vote():
    """Handles voting process end-to-end"""
    try:
        # read input from user
        vote_str = vote_entry.get().strip()
        
        if not vote_str:
            messagebox.showerror("Error", "Please enter a candidate ID")
            return
        
        # convert input to integer
        try:
            vote = int(vote_str)
        except ValueError:
            messagebox.showerror("Error", "Candidate ID must be a number")
            return
        
        # basic validation for candidate ID
        if not (1 <= vote <= 10):
            messagebox.showerror("Error", f"Candidate ID must be between 1 and 10. You entered: {vote}")
            return
        
        # make sure user is registered before voting
        if ctfE is None or ctfN is None:
            messagebox.showerror("Error", "Please register first!")
            return
        
        # Step 1: blind the vote using CTF's public key
        r, blindedVote = blind(vote, ctfE, ctfN)

        # Step 2: sign the blinded vote using voter's private key
        authSig = pow(blindedVote, voterD, voterN)

        # Step 3: send blinded vote to CTF for signing
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
            messagebox.showerror("Error", recv)
            return

        data = json.loads(recv)
        signedBlind = int(data["signedBlind"])

        # Step 4: unblind the signed message
        unblindedSig = unblind(signedBlind, r, ctfN)

        # Step 5: verify signature locally before sending
        check = pow(unblindedSig, ctfE, ctfN)
        if check != vote:
            messagebox.showerror("Error", "Local verification failed!")
            return

        # Step 6: send final vote + signature to verification authority
        payload = json.dumps({
            "choice": "cast",
            "vote": str(vote),
            "unblindedSig": str(unblindedSig)
        })
        va_socket.sendall(payload.encode())

        recv = va_socket.recv(4096).decode()
        messagebox.showinfo("Success", f"✓ Vote Cast!\n{recv}")
        vote_entry.delete(0, tk.END)
        
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        messagebox.showerror("Error", f"Error casting vote: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")


def view_results():
    """Fetch and display voting results"""
    try:
        payload = json.dumps({"choice": "results"})
        va_socket.sendall(payload.encode())
        results = va_socket.recv(4096).decode()
        
        # try parsing results nicely
        try:
            results_dict = json.loads(results)
            display_text = "📊 VOTING RESULTS\n" + "="*30 + "\n"
            
            if not results_dict:
                display_text += "No votes yet.\n"
            else:
                for candidate, votes in sorted(results_dict.items()):
                    display_text += f"Candidate {candidate}: {votes} votes\n"
        except:
            # fallback if response isn't JSON
            display_text = f"Results:\n{results}"
        
        # open a new window to show results
        results_window = tk.Toplevel(root)
        results_window.title("Voting Results")
        results_window.geometry("400x300")
        
        text_widget = scrolledtext.ScrolledText(results_window, wrap=tk.WORD, height=15, width=40)
        text_widget.pack(padx=10, pady=10)
        text_widget.insert(1.0, display_text)
        text_widget.config(state=tk.DISABLED)
        
    except Exception as e:
        messagebox.showerror("Error", f"Error fetching results: {str(e)}")


def exit_app():
    """Gracefully close sockets and exit app"""
    try:
        ctf_socket.send(b"disconnect")
        va_socket.send(b"disconnect")
        ctf_socket.close()
        va_socket.close()
        root.destroy()
    except Exception as e:
        messagebox.showerror("Error", f"Error during exit: {str(e)}")
        root.destroy()


# setup main GUI window
root = tk.Tk()
root.title("Secure Voting System")
root.geometry("500x400")
root.resizable(False, False)

# title label
title_label = tk.Label(root, text="🗳️  SECURE VOTING SYSTEM", font=("Arial", 18, "bold"))
title_label.pack(pady=15)

# container for buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# register button
register_btn = tk.Button(button_frame, text="1. Register", width=20, height=2, bg="#4CAF50", fg="white", font=("Arial", 11))
register_btn.config(command=register_voter)
register_btn.pack(pady=5)

# vote input section
vote_label = tk.Label(root, text="Vote for Candidate (1-10):", font=("Arial", 11))
vote_label.pack(pady=(10, 5))

vote_entry = tk.Entry(root, width=30, font=("Arial", 12))
vote_entry.pack(pady=5)

# cast vote button
cast_vote_btn = tk.Button(root, text="2. Cast Vote", width=20, height=2, bg="#2196F3", fg="white", font=("Arial", 11))
cast_vote_btn.config(command=cast_vote)
cast_vote_btn.pack(pady=5)

# view results button
results_btn = tk.Button(root, text="3. View Results", width=20, height=2, bg="#FF9800", fg="white", font=("Arial", 11))
results_btn.config(command=view_results)
results_btn.pack(pady=5)

# exit button
exit_btn = tk.Button(root, text="4. Exit", width=20, height=2, bg="#f44336", fg="white", font=("Arial", 11))
exit_btn.config(command=exit_app)
exit_btn.pack(pady=5)

# small status text at bottom
status_label = tk.Label(root, text="Ready", font=("Arial", 9), fg="gray")
status_label.pack(side=tk.BOTTOM, pady=5)

# start GUI loop
if __name__ == "__main__":
    root.mainloop()
