use sha2::{Sha256, Digest};
use tiny_keccak::{Keccak, Hasher};

use crate::error::EcdsaVerifyError;

pub fn secp256k1_ecdsa_recover(
    sig: &[u8; 65],
    msg: &[u8; 32],
) -> Result<[u8; 64], EcdsaVerifyError> {
    let rs = libsecp256k1::Signature::parse_overflowing_slice(&sig[0..64])
        .map_err(|_| EcdsaVerifyError::BadRS)?;
    let v = libsecp256k1::RecoveryId::parse(
        if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8
    )
    .map_err(|_| EcdsaVerifyError::BadV)?;
    let pubkey = libsecp256k1::recover(&libsecp256k1::Message::parse(msg), &rs, &v)
        .map_err(|_| EcdsaVerifyError::BadSignature)?;
    let mut res = [0u8; 64];
    res.copy_from_slice(&pubkey.serialize()[1..65]);
    Ok(res)
}

pub fn keccak_256(data: &[u8]) -> [u8; 32] {
	let mut keccak = Keccak::v256();
	keccak.update(data);
	let mut output = [0u8; 32];
	keccak.finalize(&mut output);
	output
}

pub fn sha2_256(data: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(data);
	let mut output = [0u8; 32];
	output.copy_from_slice(&hasher.finalize());
	output
}
