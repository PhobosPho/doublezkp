pragma circom 2.0.0;

include "poseidon.circom";

template VoteProof() {
    signal input nullifier;     // from ZK1
    signal input vote;          // private vote
    signal output out_nullifier;
    signal output commitment;

    component hash = Poseidon(2);
    hash.inputs[0] <== nullifier;
    hash.inputs[1] <== vote;

    out_nullifier <== nullifier;
    commitment <== hash.out;
}

component main = VoteProof();
