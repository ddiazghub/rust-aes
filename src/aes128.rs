use super::*;

pub const KEY_LEN: usize = 128 / 8;
pub const KEY_INT_LEN: usize = KEY_LEN / 4;
pub const ROUNDS: usize = 10;
pub const ITERS: usize = 10;
pub const KEYS: usize = ROUNDS + 1;

/// AES encryption algorithm using a 128 bit key
pub type AES128 = AES<{KEYS}>;

/// A Key with a size of 128 bits
pub type Key128 = Block;

impl AES128 {
    /// AES encryption algorithm using a 128 bit key
    pub fn new(key: Key128, mode: Mode) -> Self {
        Self {
            keys: Self::key_expand(key),
            mode
        }
    }

    /// Expands the given key into round keys
    fn expand(key: &Key128, i: usize) -> Key128 {
        let prev = i - 1;
        let last_word = key[key.len() - size::WORD..].try_into().unwrap();
        let mut words: [u32; KEY_INT_LEN] = Self::key_to_words(&key);
        words[0] ^= Self::g(last_word, prev);

        if cfg!(debug_assertions) {
            println!("i: {i}");
            println!("Key: {words:x?}");
            println!("Last word: {last_word:x?}");
            println!("");
        }

        for i in 1..KEY_INT_LEN {
            words[i] ^= words[i - 1];
        }

        Self::key_to_bytes(words)
    }

    /// Expands the given key into round keys
     fn key_expand(mut key: Key128) -> Keys<{KEYS}> {
        if cfg!(debug_assertions) {
            println!("Key expansion: {key:x?}");
            println!("");
        }

        let mut keys: Keys<{KEYS}> = Default::default();
        keys[0] = key;

        for i in 1..KEYS {
            key = Self::expand(&key, i);
            keys[i] = key;
        }

        if cfg!(debug_assertions) {
            println!("Output: {keys:x?}");
            println!("");
        }

        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static KEY: Block = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x46,
        0x09, 0xcf, 0x4f, 0x3c,
    ];

    #[test]
    fn test_aes128_ecb() {
        let expected = [
            0x5c, 0x46, 0x46, 0x18,
            0xe5, 0x2f, 0x79, 0x10,
            0x75, 0x41, 0x52, 0x7a,
            0xea, 0x26, 0x1a, 0x17,
        ];

        let expected2 = [
            0x5c, 0x46, 0x46, 0x18,
            0xe5, 0x2f, 0x79, 0x10,
            0x75, 0x41, 0x52, 0x7a,
            0xea, 0x26, 0x1a, 0x17,
            0x08, 0x74, 0xec, 0xc7,
            0xd2, 0x1c, 0xc6, 0x2c,
            0x8f, 0x08, 0x37, 0x70,
            0x2a, 0x67, 0x3a, 0xd6,
        ];

        let aes = AES128::new(KEY, Mode::ECB);
        aes.test(&MESSAGE, &expected);
        aes.test(&MESSAGE2, &expected2);
    }

    #[test]
    fn test_aes128_cbc() {
        let expected2 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0x06, 0x99, 0xbe, 0xb5,
            0x8a, 0x4a, 0x5e, 0x73,
            0x7e, 0x97, 0xb6, 0x64,
            0x17, 0x4c, 0xfd, 0xee,
            0xc6, 0x0a, 0x71, 0x37,
            0x86, 0x05, 0xab, 0xf8,
            0x06, 0xd8, 0x28, 0x79,
            0xfc, 0xc0, 0x46, 0xf0,
        ];

        let expected3 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0x06, 0x99, 0xbe, 0xb5,
            0x8a, 0x4a, 0x5e, 0x73,
            0x7e, 0x97, 0xb6, 0x64,
            0x17, 0x4c, 0xfd, 0xee,
            0x45, 0x78, 0x04, 0x77,
            0x44, 0xcd, 0xaf, 0x9c,
            0xd8, 0xf3, 0x86, 0x7c,
            0x1f, 0xde, 0x23, 0x6d,
            0xfb, 0x7f, 0x77, 0x5d,
            0x4b, 0x43, 0x7e, 0xd7,
            0x64, 0xbf, 0x1b, 0x74,
            0x72, 0x4e, 0x46, 0x13,
            0xee, 0x15, 0xc2, 0x23,
            0xd9, 0x44, 0x3e, 0x6f,
            0x75, 0x83, 0xda, 0x15,
            0xa2, 0x8b, 0x6e, 0x2f,        ];

        let aes = AES128::new(KEY, Mode::CBC(IV.clone()));
        aes.test(&MESSAGE2, &expected2);
        aes.test(&MESSAGE3, &expected3);
    }


    #[test]
    fn test_key_expansion() {
        let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
        let result = AES128::key_expand(key);

        let expected: [Block; aes128::KEYS] = [
            [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c],
            [0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605],
            [0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f],
            [0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b],
            [0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00],
            [0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc],
            [0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd],
            [0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f],
            [0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f],
            [0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e],
            [0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6],
        ].map(|key| key.into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
        );

        assert_eq!(result, expected);
    }
}
