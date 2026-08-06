use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use openssl::x509::X509;

fn test_compile() {
    let _m = Mechanism::Ecdsa;
    let _m2 = Mechanism::RsaPkcs;
    let _kt = KeyType::EC;
    let _kt2 = KeyType::RSA;
}
