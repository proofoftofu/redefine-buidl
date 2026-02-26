global MIMC_ROUNDS: u32 = 64;
global G: Field = 7;

fn pow7(x: Field) -> Field {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

// MiMC-like permutation for field-friendly hashing in-circuit.
fn mimc_permute(message: Field, key: Field) -> Field {
    let mut x = message + key;
    for i in 0..MIMC_ROUNDS {
        let c = (i as Field) + 1;
        x = pow7(x + c) + key;
    }
    x + key
}

fn hash2(a: Field, b: Field) -> Field {
    let s1 = mimc_permute(a, b);
    mimc_permute(b, s1)
}

fn hash4(a: Field, b: Field, c: Field, d: Field) -> Field {
    hash2(hash2(a, b), hash2(c, d))
}

fn hash5(a: Field, b: Field, c: Field, d: Field, e: Field) -> Field {
    hash2(hash4(a, b, c, d), e)
}

fn main(
    // Private credential attributes.
    dob_days: u32,
    membership: u1,
    credential_expiry_day: u32,
    holder_secret: Field,
    issuer_sig_r: Field,
    issuer_sig_s: Field,

    // Public verification inputs.
    issuer_pubkey: pub Field,
    current_day: pub u32,
    min_age_days: pub u32,
    agent_key: pub Field,
    scope_hash: pub Field,
    nullifier: pub Field,
) {
    // Attribute policy checks.
    assert(membership == 1);
    assert(current_day >= dob_days + min_age_days);
    assert(current_day <= credential_expiry_day);

    // Credential commitment includes holder secret binding to prevent sharing.
    let holder_commitment = hash2(holder_secret, agent_key);
    let credential_hash = hash4(
        dob_days as Field,
        membership as Field,
        credential_expiry_day as Field,
        holder_commitment
    );

    // Issuer signature verification (Schnorr-style relation in field model).
    // e = H(R, issuer_pubkey, credential_hash, agent_key, scope_hash)
    let e = hash5(issuer_sig_r, issuer_pubkey, credential_hash, agent_key, scope_hash);
    assert(G * issuer_sig_s == issuer_sig_r + (e * issuer_pubkey));

    // Scope-bound and agent-bound nullifier for replay protection/linkability control.
    let computed_nullifier = hash2(hash2(holder_secret, scope_hash), agent_key);
    assert(computed_nullifier == nullifier);
}
