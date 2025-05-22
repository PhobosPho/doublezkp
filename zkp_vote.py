from flask import Flask, request, jsonify
from flask_cors import CORS
import os, json, subprocess, traceback, hashlib, base64, random
from cryptography.hazmat.primitives.asymmetric import ec, dh, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
CORS(app)

# Global dictionaries for per-voter session data
SESSION_KEYS = {}           # Stores per-user derived shared keys as hex strings
SESSION_SIGNING_KEYS = {}   # Stores per-user ECDSA signing key pairs for nonce signing
SESSION_NONCE = {}          # Temporarily holds nonces for each voter session

# -------------------------------
# Server Keys and Initialization
# -------------------------------
print("🔧 zkSNARK backend: Groth16 via SnarkJS")
print("🔐 Diffie-Hellman initialized")

# Server ephemeral ECDSA signing key (for signing session nonces)
signing_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
signing_public_key = signing_private_key.public_key()

# Server ephemeral ECDH key (used in /establish-session for key exchange)
ecdh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
ecdh_public_key = ecdh_private_key.public_key()

# Generate DH parameters
dh_parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

# -------------------------------
# File Paths & Tool Constants
# -------------------------------
VOTER_DB = "voter_hashes.txt"

# ZK2: Vote Circuit (nullifier + vote → commitment)
VOTE_CIRCUIT_DIR = "vote_build"
VOTE_WASM = os.path.join(VOTE_CIRCUIT_DIR, "vote_js", "vote.wasm")
VOTE_WITNESS_JS = os.path.join(VOTE_CIRCUIT_DIR, "vote_js", "generate_witness.js")
VOTE_ZKEY = os.path.join(VOTE_CIRCUIT_DIR, "vote_final.zkey")

# ZK1: Identity Circuit (CNP + UID → nonce)
# The working circuit expects an input field named "nonce"
ZK1_DIR = "eligibility_build"
ZK1_WASM = os.path.join(ZK1_DIR, "eligibility_js", "eligibility.wasm")
ZK1_WITNESS_JS = os.path.join(ZK1_DIR, "eligibility_js", "generate_witness.js")
ZK1_ZKEY = os.path.join(ZK1_DIR, "eligibility_final.zkey")

# Paths for external tools (update these to match your installation)
NODE_PATH = "C:\\Program Files\\nodejs\\node.exe"
SNARKJS_PATH = "C:\\Users\\DELL\\AppData\\Roaming\\npm\\snarkjs.cmd"

# -------------------------------
# Helper Functions
# -------------------------------
def str_to_ascii_array(s, length=8):
    ascii_codes = [ord(c) for c in s]
    while len(ascii_codes) < length:
        ascii_codes.append(0)
    return ascii_codes[:length]

def is_valid_voter(cnp, uid):
    try:
        voter_input = f"{cnp}:{uid}"
        voter_hash = hashlib.sha256(voter_input.encode()).hexdigest()
        print(f"🔍 Checking voter hash: {voter_hash}")
        with open(VOTER_DB, "r") as f:
            return voter_hash in {line.strip() for line in f}
    except Exception:
        return False

def cleanup_files(*filenames):
    for f in filenames:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

def decrypt_with_session_key(voter_id, encrypted_data_b64, nonce_b64):
    try:
        if voter_id not in SESSION_KEYS:
            raise ValueError("Session key not found for this voter")
        key = bytes.fromhex(SESSION_KEYS[voter_id])
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(nonce_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
        return json.loads(decrypted.decode())
    except Exception as e:
        print(f"❌ Decryption error for {voter_id}: {e}")
        raise

# -------------------------------
# Endpoints
# -------------------------------

# NOTE: /exchange-key has been removed as its functionality is now incorporated into /establish-session.

# Secure Identity endpoint (ZK1)
@app.route("/secure-identity", methods=["POST"])
def secure_identity():
    try:
        data = request.get_json()
        # Expect voter_id to be passed so that we can retrieve the correct session key
        voter_id = data.get("voter_id")
        if not voter_id:
            return jsonify({"error": "Missing voter_id"}), 400
        iv = bytes(data["iv"])
        encrypted_cnp = bytes(data["cnp"])
        encrypted_uid = bytes(data["uid"])
        if voter_id not in SESSION_KEYS:
            return jsonify({"error": "Session key not found for voter"}), 400
        key = bytes.fromhex(SESSION_KEYS[voter_id])
        aesgcm = AESGCM(key)
        decrypted_cnp = aesgcm.decrypt(iv, encrypted_cnp, None).decode()
        decrypted_uid = aesgcm.decrypt(iv, encrypted_uid, None).decode()
        print(f"🔓 Decrypted CNP: {decrypted_cnp}")
        print(f"🔓 Decrypted UID: {decrypted_uid}")
        if not is_valid_voter(decrypted_cnp, decrypted_uid):
            return jsonify({"error": "Invalid voter"}), 403
        # Retrieve the session nonce previously generated for this voter
        nonce = SESSION_NONCE.get(voter_id)
        if not nonce:
            return jsonify({"error": "Session nonce not initialized"}), 400
        print(f"🔐 Using session nonce: {nonce}")
        uid_ascii = str_to_ascii_array(decrypted_uid)
        input_data = {
            "cnp": int(decrypted_cnp),
            "uid": uid_ascii,
            "nonce": nonce
        }
        with open("zk1_input.json", "w") as f:
            json.dump(input_data, f)
        subprocess.run([NODE_PATH, ZK1_WITNESS_JS, ZK1_WASM, "zk1_input.json", "zk1_witness.wtns"], check=True)
        subprocess.run([SNARKJS_PATH, "groth16", "prove", ZK1_ZKEY, "zk1_witness.wtns", "zk1_proof.json", "zk1_public.json"], check=True)
        with open("zk1_proof.json") as f:
            proof_obj = json.load(f)
        canonical = json.dumps(proof_obj, sort_keys=True, separators=(",", ":")).encode()
        zk1_hash = hashlib.sha256(canonical).hexdigest()
        hash_path = os.path.join(os.getcwd(), "zk1_proof.hash")
        with open(hash_path, "w") as f:
            f.write(zk1_hash)
        print("Updated zk1_proof.hash at", hash_path, "with hash:", zk1_hash)
        with open("zk1_public.json") as f:
            public = json.load(f)
        nullifier = public[0]
        cleanup_files("zk1_input.json", "zk1_witness.wtns")
        print(f"🧾 ZK1 Nullifier generated: {nullifier}")
        return jsonify({"status": "success", "nullifier": nullifier, "proof": proof_obj})
    except Exception as e:
        print("❌ Secure identity error:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Expose the server's ECDH public key (for key exchange during session establishment)
@app.route("/dh-server-key", methods=["GET"])
def get_server_dh_key():
    pem = ecdh_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return jsonify({"server_public_key": pem})

# Expose the server's ECDSA signing public key (for verifying nonce signatures)
@app.route("/get-server-signing-key", methods=["GET"])
def get_server_signing_key():
    pem = signing_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    print("🔑 Server signing public key served:\n", pem)
    return jsonify({"public_key": pem})

# Multi-user Session Establishment endpoint
@app.route("/establish-session", methods=["POST"])
def establish_session():
    try:
        data = request.get_json()
        voter_id = data.get("voter_id")
        client_public_key_pem = data.get("client_public_key")
        if not voter_id or not client_public_key_pem:
            return jsonify({"error": "Missing voter_id or client_public_key"}), 400
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode(), backend=default_backend())
        shared = ecdh_private_key.exchange(ec.ECDH(), client_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'zk-voting-session', backend=default_backend()).derive(shared)
        SESSION_KEYS[voter_id] = derived_key.hex()
        if voter_id not in SESSION_SIGNING_KEYS:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            SESSION_SIGNING_KEYS[voter_id] = (private_key, public_key)
            session_hash = hashlib.sha256(voter_id.encode()).hexdigest()[:10]
            print(f"🔐 ECDSA session signing key generated for session {session_hash}")
        else:
            session_hash = hashlib.sha256(voter_id.encode()).hexdigest()[:10]
            print(f"🔐 Using existing session signing keys for session {session_hash}")
        print(f"🔐 Session key established for voter {voter_id}")
        return jsonify({"status": "session_established"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Get session nonce endpoint
@app.route("/get-session-nonce", methods=["POST"])
def get_session_nonce():
    try:
        data = request.get_json()
        voter_id = data.get("voter_id")
        if not voter_id:
            return jsonify({"error": "Missing voter_id"}), 400
        private_key, _ = SESSION_SIGNING_KEYS.get(voter_id, (None, None))
        if not private_key:
            return jsonify({"error": "Session key not initialized"}), 500
        nonce = random.randint(1, 2**32)
        SESSION_NONCE[voter_id] = nonce
        nonce_bytes = str(nonce).encode("utf-8")
        signature = private_key.sign(nonce_bytes, ec.ECDSA(hashes.SHA256()))
        signature_b64 = base64.b64encode(signature).decode()
        session_hash = hashlib.sha256(voter_id.encode()).hexdigest()[:10]
        print(f"🔐 Nonce for session {session_hash}: {nonce} (signature: {signature_b64[:16]}...)")
        return jsonify({"nonce": str(nonce), "signature": signature_b64})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Get session signing key endpoint
@app.route("/get-session-signing-key", methods=["POST"])
def get_session_signing_key():
    try:
        data = request.get_json()
        voter_id = data.get("voter_id")
        if not voter_id:
            return jsonify({"error": "Missing voter_id"}), 400
        _, public_key = SESSION_SIGNING_KEYS.get(voter_id, (None, None))
        if not public_key:
            return jsonify({"error": "Session key not initialized"}), 500
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return jsonify({"public_key": pem})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Health check endpoint
@app.route("/ping")
def ping():
    return jsonify({"status": "alive"})

# Generate Vote Proof endpoint (ZK2)
@app.route("/generate-vote-proof", methods=["POST"])
def generate_vote_proof():
    data = request.get_json()
    nullifier = data.get("nullifier")
    vote = data.get("vote")
    print(f"\n🗳️ ZK2: Received nullifier={nullifier}, vote={vote}")
    if nullifier is None or vote is None:
        return jsonify({"error": "Missing nullifier or vote"}), 400
    try:
        input_data = {"nullifier": int(nullifier), "vote": int(vote)}
        with open("zk2_input.json", "w") as f:
            json.dump(input_data, f)
        subprocess.run([NODE_PATH, VOTE_WITNESS_JS, VOTE_WASM, "zk2_input.json", "zk2_witness.wtns"], check=True)
        subprocess.run([SNARKJS_PATH, "groth16", "prove", VOTE_ZKEY, "zk2_witness.wtns", "zk2_proof.json", "zk2_public.json"], check=True)
        with open("zk2_proof.json") as f:
            proof_obj = json.load(f)
        compact = json.dumps(proof_obj, sort_keys=True, separators=(",", ":")).encode()
        zk2_hash = hashlib.sha256(compact).hexdigest()
        hash_path = os.path.join(os.getcwd(), "zk2_proof.hash")
        with open(hash_path, "w") as f:
            f.write(zk2_hash)
        print("Updated zk2_proof.hash at", hash_path, "with hash:", zk2_hash)
        with open("zk2_public.json") as f:
            public = json.load(f)
        nullifier_out = public[0]
        commitment = public[1]
        cleanup_files("zk2_input.json", "zk2_witness.wtns")
        return jsonify({"status": "success", "nullifier": nullifier_out, "commitment": commitment, "proof": proof_obj})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Verify Nullifier Proof endpoint (ZK1)
@app.route("/verify-nullifier", methods=["POST"])
def verify_nullifier():
    data = request.get_json()
    print("\n🔎 ZK1: Verifying nullifier proof")
    if not data or "proof" not in data or "public" not in data:
        return jsonify({"error": "Missing proof or public"}), 400
    try:
        proof_str = json.dumps(data["proof"], sort_keys=True, separators=(",", ":")).encode()
        uploaded_hash = hashlib.sha256(proof_str).hexdigest()
        print("📥 ZK1 uploaded proof hash:", uploaded_hash)
        with open("zk1_proof.hash", "r") as f:
            expected_hash = f.read().strip()
        print("📁 ZK1 expected proof hash:", expected_hash)
        if uploaded_hash != expected_hash:
            return jsonify({"error": "Invalid proof hash — file may have been modified"}), 400
        with open("zk1_proof.json", "w") as f:
            json.dump(data["proof"], f, sort_keys=True, separators=(",", ":"))
        with open("zk1_public.json", "w") as f:
            json.dump(data["public"], f)
        verification_key_file = "eligibility_verification_key.json"
        if not os.path.exists(verification_key_file):
            return jsonify({"error": f"Missing {verification_key_file}"}), 500
        result = subprocess.run([SNARKJS_PATH, "groth16", "verify", verification_key_file, "zk1_public.json", "zk1_proof.json"], capture_output=True, text=True)
        if "OK!" in result.stdout:
            print("✅ ZK1: Proof is valid")
            with open("zk1_public.json") as f:
                pub = json.load(f)
                print("🧾 ZK1 Verified Nullifier =", pub[0])
                print("🔍 ZK1 Verification performed using Groth16")
            return jsonify({"valid": True})
        else:
            print("❌ ZK1: Invalid proof")
            print(result.stdout)
            return jsonify({"valid": False})
    except Exception as e:
        print("❌ ZK1 Verification Error:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Verify Vote Proof endpoint (ZK2)
@app.route("/verify-vote", methods=["POST"])
def verify_vote():
    data = request.get_json()
    print("\n🔎 ZK2: Verifying vote proof")
    if not data or "proof" not in data or "public" not in data:
        return jsonify({"error": "Missing proof or public"}), 400
    try:
        proof_str = json.dumps(data["proof"], sort_keys=True, separators=(",", ":")).encode()
        uploaded_hash = hashlib.sha256(proof_str).hexdigest()
        print("📥 ZK2 uploaded proof hash:", uploaded_hash)
        with open("zk2_proof.hash", "r") as f:
            expected_hash = f.read().strip()
        print("📁 ZK2 expected proof hash:", expected_hash)
        if uploaded_hash != expected_hash:
            return jsonify({"error": "Invalid proof hash — file may have been modified"}), 400
        with open("zk2_proof.json", "w") as f:
            json.dump(data["proof"], f, sort_keys=True, separators=(",", ":"))
        with open("zk2_public.json", "w") as f:
            json.dump(data["public"], f, sort_keys=True, separators=(",", ":"))
        verification_key_file = "vote_verification_key.json"
        if not os.path.exists(verification_key_file):
            return jsonify({"error": f"Missing {verification_key_file}"}), 500
        result = subprocess.run([SNARKJS_PATH, "groth16", "verify", verification_key_file, "zk2_public.json", "zk2_proof.json"], capture_output=True, text=True)
        if "OK!" in result.stdout:
            print("✅ ZK2: Proof is valid")
            with open("zk2_public.json") as f:
                pub = json.load(f)
                print("🧾 ZK2 Verified Nullifier =", pub[0])
                print("🧾 ZK2 Verified Commitment =", pub[1])
                print("🔍 ZK2 Verification performed using Groth16")
            return jsonify({"valid": True})
        else:
            print("❌ ZK2: Invalid proof")
            print(result.stdout)
            return jsonify({"valid": False})
    except Exception as e:
        print("❌ ZK2 Verification Error:")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# -------------------------------
# Start the Flask Server
# -------------------------------
if __name__ == "__main__":
    app.run(port=5000, debug=True, use_reloader=False)
