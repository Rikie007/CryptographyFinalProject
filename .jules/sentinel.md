## 2024-05-18 - [Fix Textbook RSA Authentication Forgery]
**Vulnerability:** The server verified voter authentication using raw textbook RSA signatures (`pow(authSig, voterE, voterN) == blindedVote`), allowing attackers to easily forge an `authSig` and impersonate any voter, causing a denial of service (DoS) on voting rights.
**Learning:** Textbook RSA relies on the mathematical structure of modular arithmetic without padding or hashing. It is highly vulnerable to existential forgery, where an attacker can pick a random signature and simply reverse the process (`pow(authSig, voterE, voterN)`) to craft a "valid" `blindedVote`.
**Prevention:** Always verify signatures over a cryptographic hash (like SHA-256) of the data rather than the raw data itself.
