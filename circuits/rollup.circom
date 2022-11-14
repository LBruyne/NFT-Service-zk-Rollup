pragma circom 2.0.0;
include "./merkle.circom";
include "../node_modules/circomlib/circuits/eddsamimc.circom";

template TransactionTransferVerifer() {
    var depth = 1;
    // accounts tree
    signal input old_root;
    signal input intermediate_root;
    signal output new_root;
    // account tree, each account is a leaf with pk and balance
    // signal input accounts_pubkey[2**depth][2];
    // signal input accounts_balance[2**depth];

    // transaction
    // sender leaf
    signal input sender_pubkey[2];
    signal input sender_balance;
    // receiver leaf
    signal input receiver_pubkey[2];
    signal input receiver_balance;
    // amount 
    signal input amount;
    // proof that sender and receiver exists
    signal input sender_proof[depth];
    signal input sender_proof_pos[depth];
    signal input receiver_proof[depth];
    signal input receiver_proof_pos[depth];
    // signature R(point), S
    signal input signature_R8x;
    signal input signature_R8y;
    signal input signature_S;
    signal input enabled;

    // verify sender exists in account root
    component merkleProofVerifier = MerkleProof(3, depth);
    merkleProofVerifier.leaf_in[0] <== sender_pubkey[0];
    merkleProofVerifier.leaf_in[1] <== sender_pubkey[1];
    merkleProofVerifier.leaf_in[2] <== sender_balance;
    merkleProofVerifier.root <== old_root;
    for(var i = 0; i < depth; i++) {
        merkleProofVerifier.merkle_path[i] <== sender_proof[i];
        merkleProofVerifier.merkle_path_pos[i] <== sender_proof_pos[i];
    }

    // verify signature
    component msgHasher = MultiMiMC7(5,91);
    msgHasher.k <== 1;
    msgHasher.in[0] <== sender_pubkey[0];
    msgHasher.in[1] <== sender_pubkey[1];
    msgHasher.in[2] <== receiver_pubkey[0];
    msgHasher.in[3] <== receiver_pubkey[1];
    msgHasher.in[4] <== amount; 

    component eddsaMimcVerifier = EdDSAMiMCVerifier();
    eddsaMimcVerifier.enabled <== enabled;
    eddsaMimcVerifier.Ax <== sender_pubkey[0];
    eddsaMimcVerifier.Ay <== sender_pubkey[1];
    eddsaMimcVerifier.R8x <== signature_R8x;
    eddsaMimcVerifier.R8y <== signature_R8y;
    eddsaMimcVerifier.S <== signature_S;
    eddsaMimcVerifier.M <== msgHasher.out;

    // change sender balance
    component senderLeafHasher = MultiMiMC7(3,91);
    senderLeafHasher.k <== 1;
    senderLeafHasher.in[0] <== sender_pubkey[0];
    senderLeafHasher.in[1] <== sender_pubkey[1];
    senderLeafHasher.in[2] <== sender_balance - amount;
    // check intermediate root
    component intermediateMerkleRootComputer = MerkleRoot(depth);
    intermediateMerkleRootComputer.leaf <== senderLeafHasher.out;
    for(var i = 0; i < depth; i++) {
        intermediateMerkleRootComputer.merkle_path[i] <== sender_proof[i];
        intermediateMerkleRootComputer.merkle_path_pos[i] <== sender_proof_pos[i];
    }
    intermediateMerkleRootComputer.root === intermediate_root;

    // verify receiver exists in intermediate tree
    component receiverMerkleProofVerifier = MerkleProof(3, depth);
    receiverMerkleProofVerifier.leaf_in[0] <== receiver_pubkey[0];
    receiverMerkleProofVerifier.leaf_in[1] <== receiver_pubkey[1];
    receiverMerkleProofVerifier.leaf_in[2] <== receiver_balance;
    receiverMerkleProofVerifier.root <== intermediate_root;
    for(var i = 0; i < depth; i++) {
        receiverMerkleProofVerifier.merkle_path[i] <== receiver_proof[i];
        receiverMerkleProofVerifier.merkle_path_pos[i] <== receiver_proof_pos[i];
    }

    // change receiver balance
    component receiverLeafHasher = MultiMiMC7(3,91);
    receiverLeafHasher.k <== 1;
    receiverLeafHasher.in[0] <== receiver_pubkey[0];
    receiverLeafHasher.in[1] <== receiver_pubkey[1];
    receiverLeafHasher.in[2] <== receiver_balance + amount;

    // update root
    component newMerkleRootComputer = MerkleRoot(depth);
    newMerkleRootComputer.leaf <== receiverLeafHasher.out;
    for(var i = 0; i < depth; i++){
        newMerkleRootComputer.merkle_path[i] <== receiver_proof[i];
        newMerkleRootComputer.merkle_path_pos[i] <== receiver_proof_pos[i];
    }

    // output   
    new_root <== newMerkleRootComputer.root;
}

component main{public [old_root, intermediate_root]} = TransactionTransferVerifer();