pub mod aes128;
pub mod aes192;
pub mod aes256;
mod tables;
mod block;
mod f256;

pub use aes128::AES128;
pub use aes192::AES192;
pub use aes256::AES256;

use tables::{mix, RC, sbox};
use block::{Block, BlockMatrix};
use test_constants::*;

/// Size constants
mod size {
    /// Size of a block in bytes
    pub const BLOCK: usize = 128 / 8;

    /// 4 bytes
    pub const WORD: usize = 4;
}

type InitVector = Block;

pub enum Mode<'a> {
    ECB,
    CBC(InitVector),
    Counter(&'a [u8]),
}

/// An AES Key of size T
type Key<const T: usize> = [u8; T];

/// An AES Key of size T
type Keys<const K: usize> = [Block; K];

/// AES encryption algorithm
pub struct AES<'a, const K: usize> {
    /// Round keys used for encryption
    keys: Keys<K>,
    mode: Mode<'a>
}

impl<'a, const K: usize> AES<'a, K> {
    pub fn with_keys(keys: Keys<K>, mode: Mode<'a>) -> Self {
        Self {
            keys,
            mode
        }
    }

    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        match &self.mode {
            Mode::ECB => self.ecb_encrypt(message),
            Mode::CBC(iv) => self.cbc_encrypt(message, iv),
            Mode::Counter(ci) => self.counter_encrypt(message, ci)
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        match self.mode {
            Mode::ECB => self.ecb_decrypt(ciphertext),
            Mode::CBC(_) => self.cbc_decrypt(ciphertext),
            Mode::Counter(ci) => self.counter_encrypt(ciphertext, ci)
        }
    }

    pub fn partial_round(&self, mut bytes: Block, key: usize) -> Block {
        bytes = Self::byte_sub(bytes);
        bytes = BlockMatrix(bytes).shift_rows().0;

        f256::add_words(&bytes, &self.keys[key])
    }

    pub fn round(&self, mut bytes: Block, key: usize) -> Block {
        bytes = Self::byte_sub(bytes);
        bytes = BlockMatrix(bytes).shift_rows().mix_columns().0;

        f256::add_words(&bytes, &self.keys[key])
    }

    /// Encrypt the given message
    pub fn encrypt_block(&self, message: Block) -> Block {
        if cfg!(debug_assertions) {
            println!("Block encryption:");
            println!("Input: {message:x?}");
            println!("");
        }

        let mut ciphertext = f256::add_words(&message, &self.keys[0]);

        for key in 1..self.keys.len() - 1 {
            ciphertext = self.round(ciphertext, key);
        }

        ciphertext = self.partial_round(ciphertext, self.keys.len() - 1);

        if cfg!(debug_assertions) {
            println!("Encrypted block: {ciphertext:x?}");
        }

        ciphertext
    }

    pub fn ecb_encrypt(&self, message: &[u8]) -> Vec<u8> {
        let padded = Self::pad(message);

        if cfg!(debug_assertions) {
            println!("AES ECB encryption:");
            println!("Input: {message:x?}");
            println!("Padded message: {padded:x?}");
            println!("");
        }

        let ciphertext = Self::partition(&padded)
            .flat_map(|block| self.encrypt_block(block.try_into().unwrap()))
            .collect();

        if cfg!(debug_assertions) {
            println!("Encrypted: {ciphertext:x?}");
        }

        ciphertext
    }

    pub fn cbc_encrypt(&self, message: &[u8], iv: &Block) -> Vec<u8> {
        let padded = Self::pad(message);

        if cfg!(debug_assertions) {
            println!("AES CBC encryption:");
            println!("Input: {message:x?}");
            println!("Padded message: {padded:x?}");
            println!("");
        }

        let mut partitions = vec![iv.clone()];

        for block in Self::partition(&padded) {
            let chained = f256::add_words(block.try_into().unwrap(), partitions.last().unwrap());
            partitions.push(self.encrypt_block(chained));
        }

        let ciphertext = partitions.concat();

        if cfg!(debug_assertions) {
            println!("Encrypted: {ciphertext:x?}");
        }

        ciphertext
    }

    pub fn counter_encrypt(&self, message: &[u8], ci: &[u8]) -> Vec<u8> {
        if cfg!(debug_assertions) {
            println!("AES Counter encryption/decryption:");
            println!("Input: {message:x?}");
            println!("");
        }

        let (len_iv, iv) = Self::get_iv(ci);
        let (counter_max, mut counter) = Self::get_counter(len_iv);
        let mut ciphertext = Vec::new();

        for block in Self::partition(message) {
            let iv_counter = Self::iv_counter_concat(&iv, len_iv, counter);
            let encrypted = self.encrypt_block(iv_counter);
            ciphertext.extend_from_slice(&f256::add_slices(&encrypted, block));
            counter = (counter + 1) & counter_max;
        }

        if cfg!(debug_assertions) {
            println!("Encrypted/Decrypted: {ciphertext:x?}");
        }

        ciphertext
    }

    fn get_iv(ci: &[u8]) -> (usize, Block) {
        let mut iv: Block = Default::default();
        iv[..ci.len()].copy_from_slice(ci);

        (ci.len(), iv)
    }

    fn get_counter(len_iv: usize) -> (u128, u128) {
        ((1 << size::BLOCK - len_iv) - 1, 0)
    }

    fn iv_counter_concat(iv: &Block, len_iv: usize, counter: u128) -> Block {
        let mut iv_counter = iv.clone();
        let counter_bytes = counter.to_be_bytes();
        iv_counter[len_iv..].copy_from_slice(&counter_bytes[counter_bytes.len() - (size::BLOCK - len_iv)..]);

        iv_counter
    }

    pub fn inv_partial_round(&self, mut bytes: Block, key: usize) -> Block {
        bytes = f256::add_words(&bytes, &self.keys[key]);
        bytes = BlockMatrix(bytes).inv_shift_rows().0;

        Self::inv_byte_sub(bytes)
    }

    pub fn inv_round(&self, mut bytes: Block, key: usize) -> Block {
        bytes = f256::add_words(&bytes, &self.keys[key]);
        bytes = BlockMatrix(bytes).inv_mix_columns().inv_shift_rows().0;

        Self::inv_byte_sub(bytes)
    }

    /// Decrypt the given message
    pub fn decrypt_block(&self, ciphertext: Block) -> Block {
        if cfg!(debug_assertions) {
            println!("Block decryption:");
            println!("Input: {ciphertext:x?}");
            println!("");
        }

        let mut message = self.inv_partial_round(ciphertext, self.keys.len() - 1);

        for key in (1..self.keys.len() - 1).rev() {
            message = self.inv_round(message, key);
        }

        message = f256::add_words(&message, &self.keys[0]);

        if cfg!(debug_assertions) {
            println!("Decrypted block: {message:x?}");
        }

        message
    }

    pub fn ecb_decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        if cfg!(debug_assertions) {
            println!("AES ECB decryption:");
            println!("Input: {ciphertext:x?}");
            println!("");
        }

        let message: Vec<_> = Self::partition(ciphertext)
            .flat_map(|block| self.decrypt_block(block.try_into().unwrap()))
            .collect();

        let message = Self::unpad(&message);

        if cfg!(debug_assertions) {
            println!("Decrypted: {message:x?}");
        }

        message
    }

    pub fn cbc_decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        if cfg!(debug_assertions) {
            println!("AES CBC decryption:");
            println!("Input: {ciphertext:x?}");
            println!("");
        }

        let blocks: Vec<_> = Self::partition(ciphertext).collect();
        let mut partitions = vec![blocks[0].try_into().unwrap()];

        for pair in blocks.windows(2) {
            let decrypted = self.decrypt_block(pair[1].try_into().unwrap());
            partitions.push(f256::add_words(&decrypted, pair[0].try_into().unwrap()));
        }

        let message = Self::unpad(&partitions[1..].concat());

        if cfg!(debug_assertions) {
            println!("Decrypted: {message:x?}");
        }

        message
    }

    /// Round keys used for encryption
    pub fn keys(&self) -> &Keys<K> {
        &self.keys
    }

    /// Performs byte substitution on an array of bytes using the S-Box
    fn byte_sub<const S: usize>(bytes: [u8; S]) -> [u8; S] {
        bytes.map(|byte| sbox::FORWARD[byte as usize])
    }

    /// Performs byte substitution on an array of bytes using the inverse S-Box
    fn inv_byte_sub<const S: usize>(bytes: [u8; S]) -> [u8; S] {
        bytes.map(|byte| sbox::INVERSE[byte as usize])
    }

    /// AES G function
    fn g(mut word: [u8; size::WORD], i: usize) -> u32 {
        word.rotate_left(1);
        let mut output = Self::byte_sub(word);
        output[0] ^= RC[i];

        u32::from_be_bytes(output)
    }

    /// AES H function
    fn h(word: [u8; size::WORD]) -> u32 {
        u32::from_be_bytes(Self::byte_sub(word))
    }

    /// Transforms an AES Key from its byte array representation, to a 32 bit unsigned integer
    /// array representation. Groups of 4 bytes are made to create each integer.
    fn key_to_words<const S: usize, const W: usize>(key: &Key<S>) -> [u32; W] {
        let mut words = [0; W];

        for (i, chunk) in key.chunks(size::WORD).enumerate() {
            words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        words
    }

    /// Transforms an AES Key from its u32 array representation to an array of bytes.
    fn key_to_bytes<const S: usize, const W: usize>(key: [u32; W]) -> Key<S> {
        let mut bytes = [0; S];

        for (i, byte) in key.into_iter().flat_map(u32::to_be_bytes).enumerate() {
            bytes[i] = byte;
        }

        bytes
    }

    fn pad(message: &[u8]) -> Vec<u8> {
        let padding = (size::BLOCK - message.len() % size::BLOCK) % size::BLOCK;
        let mut padded = Vec::from_iter(message.into_iter().copied());
        padded.resize(message.len() + padding, padding as u8);

        padded
    }

    fn unpad(message: &[u8]) -> Vec<u8> {
        let mut padding = message[message.len() - 1];

        match padding {
            0..=15 => {
                if message[message.len() - padding as usize..message.len() - 1].iter().copied().any(|byte| byte != padding) {
                    padding = 0;
                }
            },
            _ => padding = 0
        }

        Vec::from_iter(message.into_iter().take(message.len() - padding as usize).copied())
    }

    fn partition(message: &[u8]) -> impl Iterator<Item = &[u8]> {
        message.chunks(size::BLOCK)
    }

    fn test(&self, message: &[u8], expected: &[u8]) {
        let ciphertext = self.encrypt(&message);
        assert_eq!(ciphertext, expected);
        let plaintext = self.decrypt(&ciphertext);
        assert_eq!(plaintext, message);
    }
}

mod test_constants {
    use super::*;

    pub static IV: Block =[
        0x40, 0x56, 0x3d, 0x95,
        0xb6, 0xcc, 0x11, 0x6e,
        0x43, 0xde, 0x5d, 0x47,
        0xcd, 0x54, 0x06, 0x76,
    ];

    pub static MESSAGE: Block = [
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
    ];

    pub static MESSAGE2: [u8; 24] = [
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
    ];

    pub static MESSAGE3: [u8; 50] = [
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x5a, 0x30,
    ];
}

#[cfg(test)]
mod tests {
    use crate::{aes128::Key128, aes192::Key192, aes256::Key256};
    use super::*;

    #[test]
    fn test_key_to_words() {
        let key = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C
        ];

        let result: [u32; size::WORD] = AES128::key_to_words(&key);

        let expected = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C
        ];

        assert_eq!(result, expected);

        let key = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x16, 0x28, 0xAE, 0x00,
            0x2B, 0x7E, 0x15, 0x16
        ];

        let result: [u32; aes192::KEY_INT_LEN] = AES192::key_to_words(&key);

        let expected = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C,
            0x1628AE00,
            0x2B7E1516,
        ];

        assert_eq!(result, expected);

        let key = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x16, 0x28, 0xAE, 0x00,
            0x2B, 0x7E, 0x15, 0x16,
            0xCF, 0x4F, 0x3C, 0x16,
            0x88, 0x09, 0xCF, 0x4F,
        ];

        let result: [u32; aes256::KEY_INT_LEN] = AES256::key_to_words(&key);

        let expected = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C,
            0x1628AE00,
            0x2B7E1516,
            0xCF4F3C16,
            0x8809CF4F,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_key_to_bytes() {
        let key = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C
        ];

        let expected: Key128 = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C
        ];

        let result: Key128 = AES128::key_to_bytes(key);

        assert_eq!(result, expected);

        let key = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C,
            0x1628AE00,
            0x2B7E1516,
        ];

        let result: Key192 = AES192::key_to_bytes(key);

        let expected = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x16, 0x28, 0xAE, 0x00,
            0x2B, 0x7E, 0x15, 0x16
        ];

        assert_eq!(result, expected);

        let key = [
            0x2B7E1516,
            0x28AED2A6,
            0xABF71588,
            0x09CF4F3C,
            0x1628AE00,
            0x2B7E1516,
            0xCF4F3C16,
            0x8809CF4F,
        ];

        let result: Key256 = AES256::key_to_bytes(key);

        let expected = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x16, 0x28, 0xAE, 0x00,
            0x2B, 0x7E, 0x15, 0x16,
            0xCF, 0x4F, 0x3C, 0x16,
            0x88, 0x09, 0xCF, 0x4F,
        ];


        assert_eq!(result, expected);
    }

    #[test]
    fn test_mix_columns() {
        // Case 1
        let block: Block = [
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
        ];

        let expected: Block = [
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
        ];

        assert_eq!(BlockMatrix(block).mix_columns().0, expected);

        // Case 2
        let block: Block = [
            0x63, 0x2F, 0xAF, 0xA2,
            0xEB, 0x93, 0xC7, 0x20,
            0x9F, 0x92, 0xAB, 0xCB,
            0xA0, 0xC0, 0x30, 0x2B,
        ];

        let expected: Block = [
            0xBA, 0x75, 0xF4, 0x7A,
            0x84, 0xA4, 0x8D, 0x32,
            0xE8, 0x8D, 0x06, 0x0E,
            0x1B, 0x40, 0x7D, 0x5D
        ];

        assert_eq!(BlockMatrix(block).mix_columns().0, expected);
    }
}
