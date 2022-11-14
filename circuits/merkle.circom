pragma circom 2.0.0;
include "../node_modules/circomlib/circuits/mimc.circom";

template MerkleProof(length, depth) {
    signal input leaf_in[length];
    signal input root;
    signal input merkle_path[depth];
    signal input merkle_path_pos[depth];

    component leafComputer = MultiMiMC7(length, 91);
    leafComputer.k <== 1;

    for(var i = 0; i < length; i++) {
        leafComputer.in[i] <== leaf_in[i];
    }

    component merkleRootComputer = MerkleRoot(depth);
    merkleRootComputer.leaf <== leafComputer.out;

    for(var i = 0; i < depth; i++) {
        merkleRootComputer.merkle_path[i] <== merkle_path[i];
        merkleRootComputer.merkle_path_pos[i] <== merkle_path_pos[i];
    }

    // constraint: input root === computed root
    root === merkleRootComputer.root;
}

template MerkleRoot(depth) {
    // depth
    signal input leaf;
    signal input merkle_path[depth];
    signal input merkle_path_pos[depth];

    signal output root;

    component selectors[depth];
    component hashers[depth];
    for(var i = 0; i < depth; i++) {
        selectors[i] = Selector();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i-1].out;
        selectors[i].in[1] <== merkle_path[i];
        selectors[i].select <== merkle_path_pos[i];

        hashers[i] = MultiMiMC7(2,91);
        hashers[i].k <== 1;
        hashers[i].in[0] <== selectors[i].out[0];
        hashers[i].in[1] <== selectors[i].out[1];
    }

    root <== hashers[depth-1].out;
}

// select the correct brother according to the pos
template Selector() {
    signal input in[2];
    signal input select;
    signal output out[2];

    select * (select-1) === 0;
    out[0] <== (in[1] - in[0]) * select + in[0];
    out[1] <== (in[0] - in[1]) * select + in[1];
}