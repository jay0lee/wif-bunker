fn main() {
    println!("OpenSSL version: {:x}", unsafe { openssl_sys::OpenSSL_version_num() });
}
