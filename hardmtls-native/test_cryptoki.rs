use cryptoki::context::Pkcs11;
use cryptoki::slot::Slot;

fn main() {
    // try to get from u64
    let _s: Slot = 0u64.into();
}
