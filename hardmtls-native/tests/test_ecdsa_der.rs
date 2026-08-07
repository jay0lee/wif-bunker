use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

#[test]
fn test_encode() {
    let r = BigNum::from_slice(&[1, 2, 3]).unwrap();
    let s = BigNum::from_slice(&[4, 5, 6]).unwrap();
    let sig = EcdsaSig::from_private_components(r, s).unwrap();
    let der = sig.to_der().unwrap();
    println!("DER: {:?}", der);
}
