use super::*;

pub const KEY_LEN: usize = 256 / 8;
pub const KEY_INT_LEN: usize = KEY_LEN / 4;
pub const ROUNDS: usize = 14;
pub const ITERS: usize = 7;
pub const KEYS: usize = ROUNDS + 1;

/// AES encryption algorithm using a 192 bit key
pub type AES256 = AES<{KEYS}>;

/// A Key with a size of 192 bits
pub type Key256 = Key<{aes256::KEY_LEN}>;

impl AES256 {
    /// AES encryption algorithm using a 128 bit key
    pub fn new(key: Key256, mode: Mode) -> Self {
        Self {
            keys: Self::key_expand(key),
            mode
        }
    }

    /// Expands the given key into round keys
    fn expand(key: &Key256, i: usize) -> Key256 {
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

        for j in 1..4 {
            words[j] ^= words[j - 1];
        }

        words[4] ^= Self::h(words[3].to_be_bytes());

        for j in 5..KEY_INT_LEN {
            words[j] ^= words[j - 1];
        }

        Self::key_to_bytes(words)
    }

    /// Expands the given key into round keys
    fn key_expand(mut key: Key256) -> Keys<{KEYS}> {
        if cfg!(debug_assertions) {
            println!("Key expansion: {key:x?}");
            println!("");
        }

        let mut keys: Keys<{KEYS}> = Default::default();
        keys[0].copy_from_slice(&key[..size::BLOCK]);
        keys[1].copy_from_slice(&key[size::BLOCK..]);

        for i in 1..ITERS {
            key = Self::expand(&key, i);
            keys[2 * i].copy_from_slice(&key[..size::BLOCK]);
            keys[2 * i + 1].copy_from_slice(&key[size::BLOCK..]);
        }

        key = Self::expand(&key, ITERS);
        keys.last_mut().unwrap().copy_from_slice(&key[..size::BLOCK]);

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

    static KEY: Key256 = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x46,
        0x09, 0xcf, 0x4f, 0x3c,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x30, 0x8d, 0x31, 0x31,
        0x98, 0xa2, 0xe0, 0x37,
    ];


    #[test]
    fn test_aes256_ecb() {
        let expected = [
            0x0a, 0x37, 0x8a, 0x0d,
            0xab, 0x5a, 0x09, 0xe7,
            0xd9, 0xad, 0xab, 0x9e,
            0x21, 0x2a, 0xb1, 0x60
        ];

        let expected2 = [
            0x0a, 0x37, 0x8a, 0x0d,
            0xab, 0x5a, 0x09, 0xe7,
            0xd9, 0xad, 0xab, 0x9e,
            0x21, 0x2a, 0xb1, 0x60,
            0x7b, 0x46, 0x52, 0xe1,
            0xce, 0x6f, 0x8a, 0x81,
            0xcb, 0xb0, 0xd7, 0xf2,
            0xe5, 0x3b, 0xd4, 0xce,
        ];

        let aes = AES256::new(KEY, Mode::ECB);
        aes.test(&MESSAGE, &expected);
        aes.test(&MESSAGE2, &expected2);
    }

    #[test]
    fn test_aes256_cbc() {
        let expected2 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0x43, 0x2d, 0xc6, 0x5e,
            0x98, 0x3c, 0xcb, 0xce,
            0xbf, 0x93, 0x68, 0xc5,
            0x4d, 0xb8, 0xae, 0x05,
            0xbb, 0x4d, 0x48, 0x19,
            0x1c, 0xbb, 0x6a, 0x5e,
            0xa2, 0x24, 0xa5, 0xcc,
            0x6a, 0x76, 0x25, 0xf5,
        ];

        let expected3 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0x43, 0x2d, 0xc6, 0x5e,
            0x98, 0x3c, 0xcb, 0xce,
            0xbf, 0x93, 0x68, 0xc5,
            0x4d, 0xb8, 0xae, 0x05,
            0x96, 0xee, 0xa8, 0x52,
            0x3f, 0x30, 0x8a, 0x9f,
            0x04, 0xb7, 0x82, 0x33,
            0xf2, 0x94, 0xe7, 0x3e,
            0xc4, 0x08, 0xdb, 0xa8,
            0x48, 0xc7, 0xe4, 0xe8,
            0xeb, 0xab, 0x05, 0x91,
            0xd5, 0x83, 0xfa, 0x60,
            0xe5, 0x30, 0xeb, 0x84,
            0xb9, 0xb5, 0xa6, 0xe2,
            0xb9, 0x2b, 0x17, 0xcc,
            0xc5, 0xac, 0x1a, 0x50,
        ];

        let aes = AES256::new(KEY, Mode::CBC(IV.clone()));
        aes.test(&MESSAGE2, &expected2);
        aes.test(&MESSAGE3, &expected3);
    }

    #[test]
    fn test_key_expansion() {
        let key: Key256 = [
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x46,
            0x09, 0xcf, 0x4f, 0x3c,
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
            0x30, 0x8d, 0x31, 0x31,
            0x98, 0xa2, 0xe0, 0x37,
        ];

        let result = AES256::key_expand(key);

        let expected: [Block; aes256::KEYS] = [
            [0x2b7e1516, 0x28aed2a6, 0xabf79746, 0x09cf4f3c],
            [0x3243f6a8, 0x885a308d, 0x308d3131, 0x98a2e037],
            [0x109f8f50, 0x38315df6, 0x93c6cab0, 0x9a09858c],
            [0x8a4261cc, 0x02185141, 0x32956070, 0xaa378047],
            [0x88522ffc, 0xb063720a, 0x23a5b8ba, 0xb9ac3d36],
            [0xdcd346c9, 0xdecb1788, 0xec5e77f8, 0x4669f7bf],
            [0x753a27a6, 0xc55955ac, 0xe6fced16, 0x5f50d020],
            [0x1380367e, 0xcd4b21f6, 0x2115560e, 0x677ca1b1],
            [0x6d08ef23, 0xa851ba8f, 0x4ead5799, 0x11fd87b9],
            [0x91d42128, 0x5c9f00de, 0x7d8a56d0, 0x1af6f761],
            [0x3f600081, 0x9731ba0e, 0xd99ced97, 0xc8616a2e],
            [0x793b2319, 0x25a423c7, 0x582e7517, 0x42d88276],
            [0x7e7338ad, 0xe94282a3, 0x30de6f34, 0xf8bf051a],
            [0x383348bb, 0x1d976b7c, 0x45b91e6b, 0x07619c1d],
            [0xd1ad9c68, 0x38ef1ecb, 0x083171ff, 0xf08e74e5],
        ].map(|key| key.into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
        );

        assert_eq!(result, expected);
    }
}
