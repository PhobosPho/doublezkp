# hash_voter_db.py
import hashlib

with open("voter_database.txt", "r") as infile, open("voter_hashes.txt", "w") as outfile:
    for line in infile:
        line = line.strip()
        if not line or ":" not in line:
            continue
        cnp, uid = line.split(":")
        combined = f"{cnp}:{uid}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        outfile.write(hashed + "\n")

print("✅ Hashed voter database written to voter_hashes.txt")
