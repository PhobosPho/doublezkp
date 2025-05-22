pragma circom 2.0.0;
include "poseidon.circom";

template EligibilityCheck() {
    signal input cnp;
    signal input uid[8];
    signal input nonce;

    signal output nullifier;

    signal uid_product[8];
    signal a;
    signal b;
    signal c;

    uid_product[0] <== uid[0];
    for (var i = 1; i < 8; i++) {
        uid_product[i] <== uid_product[i - 1] * uid[i];
    }

    a <== cnp * uid_product[7];
    b <== a + nonce;
    c <== b * b;

    component hasher = Poseidon(1);
    hasher.inputs[0] <== c;

    nullifier <== hasher.out;
}

component main = EligibilityCheck();
