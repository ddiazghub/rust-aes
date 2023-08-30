use super::*;

pub const KEY_LEN: usize = 192 / 8;
pub const KEY_INT_LEN: usize = KEY_LEN / 4;
pub const ROUNDS: usize = 12;
pub const ITERS: usize = 8;
pub const KEYS: usize = ROUNDS + 1;

/// AES encryption algorithm using a 192 bit key
pub type AES192 = AES<{KEYS}>;
///
/// A Key with a size of 192 bits
pub type Key192 = Key<{aes192::KEY_LEN}>;

impl AES192 {
    /// AES encryption algorithm using a 128 bit key
    pub fn new(key: Key192, mode: Mode) -> Self {
        Self {
            keys: Self::key_expand(key),
            mode
        }
    }

    /// Expands the given key into round keys
    fn expand(key: &Key192, i: usize) -> Key192 {
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
    fn key_expand(mut key: Key192) -> Keys<{KEYS}> {
        if cfg!(debug_assertions) {
            println!("Key expansion: {key:x?}");
            println!("");
        }

        const BYTES_LEN: usize = KEYS * size::BLOCK;
        let mut bytes = [0; BYTES_LEN];
        bytes[..KEY_LEN].copy_from_slice(&key);

        for i in 1..ITERS {
            key = Self::expand(&key, i);
            bytes[KEY_LEN * i..KEY_LEN * (i + 1)].copy_from_slice(&key);
        }

        key = Self::expand(&key, ITERS);
        bytes[BYTES_LEN - size::BLOCK..].copy_from_slice(&key[..size::BLOCK]);

        let mut keys: Keys<{KEYS}> = Default::default();

        for (i, subkey) in bytes.chunks(size::BLOCK).enumerate() {
            keys[i].copy_from_slice(subkey);
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

    static KEY: Key192 = [
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x46,
        0x09, 0xcf, 0x4f, 0x3c,
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
    ];

    #[test]
    fn test_aes192_ecb() {
        let expected = [
            0xcc, 0x04, 0x01, 0xc0,
            0xfa, 0xe3, 0xea, 0x1b,
            0xe9, 0x08, 0x5c, 0xef,
            0xa3, 0x19, 0xd6, 0x29
        ];

        let expected2 = [
            0xcc, 0x04, 0x01, 0xc0,
            0xfa, 0xe3, 0xea, 0x1b,
            0xe9, 0x08, 0x5c, 0xef,
            0xa3, 0x19, 0xd6, 0x29,
            0x38, 0x8c, 0x3b, 0xc9,
            0xa0, 0x2f, 0x66, 0x7f,
            0xfa, 0x64, 0x5d, 0xed,
            0xc2, 0xbd, 0x62, 0x35,
        ];

        let aes = AES192::new(KEY, Mode::ECB);
        aes.test(&MESSAGE, &expected);
        aes.test(&MESSAGE2, &expected2);
    }

    #[test]
    fn test_aes192_cbc() {
        let expected2 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0xf4, 0x91, 0xd1, 0xeb,
            0x78, 0xc0, 0xa6, 0x38,
            0x4f, 0x51, 0xed, 0xa2,
            0x3c, 0x91, 0xca, 0x6f,
            0x60, 0x51, 0x5b, 0xd1,
            0x94, 0xea, 0x9f, 0x38,
            0xfa, 0xfe, 0x70, 0xee,
            0x8d, 0x1b, 0x1e, 0xa1,        ];

        let expected3 = [
            0x40, 0x56, 0x3d, 0x95,
            0xb6, 0xcc, 0x11, 0x6e,
            0x43, 0xde, 0x5d, 0x47,
            0xcd, 0x54, 0x06, 0x76,
            0xf4, 0x91, 0xd1, 0xeb,
            0x78, 0xc0, 0xa6, 0x38,
            0x4f, 0x51, 0xed, 0xa2,
            0x3c, 0x91, 0xca, 0x6f,
            0xef, 0x64, 0xdc, 0x3c,
            0xd3, 0xed, 0xcc, 0xf8,
            0x2b, 0xde, 0x2c, 0x58,
            0xac, 0xf0, 0x6b, 0x22,
            0x12, 0xae, 0x5f, 0x85,
            0x24, 0x77, 0xc7, 0x2f,
            0x22, 0xef, 0x41, 0x62,
            0x5d, 0xc1, 0x71, 0xd0,
            0xfa, 0xb3, 0xe2, 0xd7,
            0x36, 0xea, 0x35, 0x59,
            0xe4, 0x99, 0x51, 0x52,
            0x11, 0xe0, 0x23, 0x85,        ];

        let aes = AES192::new(KEY, Mode::CBC(IV.clone()));
        aes.test(&MESSAGE2, &expected2);
        aes.test(&MESSAGE3, &expected3);
    }

    #[test]
    fn test_key_expansion() {
        let key: Key192 = [
            0x2B, 0x7E, 0x15, 0x16,
            0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,
            0x09, 0xCF, 0x4F, 0x3C,
            0x32, 0x43, 0xf6, 0xa8,
            0x88, 0x5a, 0x30, 0x8d,
        ];

        let result = AES192::key_expand(key);

        let expected: [Block; aes192::KEYS] = [
            [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c],
            [0x3243f6a8, 0x885a308d, 0x947a48d2, 0xbcd49a74],
            [0x17238ffc, 0x1eecc0c0, 0x2caf3668, 0xa4f506e5],
            [0x7015919b, 0xccc10bef, 0xdbe28413, 0xc50e44d3],
            [0xe9a172bb, 0x4d54745e, 0x5487c978, 0x9846c297],
            [0x43a44684, 0x86aa0257, 0x6f0b70ec, 0x225f04b2],
            [0x9375feeb, 0x0b333c7c, 0x48977af8, 0xce3d78af],
            [0xa1360843, 0x83690cf1, 0x7a8b5f07, 0x71b8637b],
            [0x392f1983, 0xf712612c, 0x5624696f, 0xd54d659e],
            [0xb9c65404, 0xc87e377f, 0xf1512efc, 0x06434fd0],
            [0x506726bf, 0x852a4321, 0x1cdca993, 0xd4a29eec],
            [0x25f3b010, 0x23b0ffc0, 0x73d7d97f, 0xf6fd9a5e],
            [0xc864f1d1, 0x1cc66f3d, 0x3935df2d, 0x1a8520ed],
        ].map(|key| key.into_iter()
            .flat_map(u32::to_be_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
        );

        assert_eq!(result, expected);
    }
}
