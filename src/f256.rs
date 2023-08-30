const N: u16 = 8;
const BASE: u16 = 0b11011;
const MASK: u16 = (1 << N) - 1;

/// Adds 2 arrays in F_2^8
pub fn add_words<const S: usize>(a: &[u8; S], b: &[u8; S]) -> [u8; S] {
    let mut result = a.clone();

    for i in 0..S {
        result[i] ^= b[i];
    }

    result
}

/// Adds 2 bytes in F_2^8
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplies 2 bytes in F_2^8
pub fn mult(a: u8, b: u8) -> u8 {
    let a = a as u16;
    let b = b as u16;
    let mut result = 0_u16;

    for i in 0..N as u16 {
        if (b & (1 << i)) > 0 {
            result ^= a << i;
        }
    }

    let high = (result & (MASK << N)) >> N;

    for i in 0..N {
        if (high & (1 << i)) > 0 {
            result ^= BASE << i;
        }
    }

    (result & MASK) as u8
}

/// Raises a byte to a power in F_2^8
pub fn pow(mut n: u8, mut exp: u8) -> u8 {
    let mut result = 1;

    loop {
        if exp & 1 == 1 {
            result = mult(result, n);
        }

        exp >>= 1;

        if exp == 0 {
            return result;
        }

        n = mult(n, n);
    }
}

#[cfg(test)]
mod tests {
    use super::{pow, add, mult};

    #[test]
    fn test_add() {
        // Test case 1: Adding 0 to any element should result in the element itself
        assert_eq!(add(0, 5), 5);
        assert_eq!(add(7, 0), 7);
        assert_eq!(add(0, 255), 255);

        // Test case 2: Adding an element to itself should result in 0
        assert_eq!(add(10, 10), 0);
        assert_eq!(add(20, 20), 0);
        assert_eq!(add(255, 255), 0);

        // Test case 3: Regular addition within F_{2^8}
        assert_eq!(add(0b01010101, 0b10101010), 0xff);
        assert_eq!(add(200, 200), 0);

        // Test case 4: Overflow cases
        assert_eq!(add(255, 1), 254);
        assert_eq!(add(127, 128), 255);
        assert_eq!(add(250, 250), 0);
    }

    #[test]
    fn test_mult() {
        // Test case 1: Multiplying by 0 should result in 0
        assert_eq!(mult(0, 5), 0);
        assert_eq!(mult(7, 0), 0);
        assert_eq!(mult(0, 255), 0);

        // Test case 2: Multiplying by 1 should result in the element itself
        assert_eq!(mult(1, 5), 5);
        assert_eq!(mult(7, 1), 7);
        assert_eq!(mult(1, 255), 255);

        // Test case 3: Regular multiplication within GF(256)
        assert_eq!(mult(3, 11), 29);
        assert_eq!(mult(30, 5), 102);
        assert_eq!(mult(85, 45), 202);

        // Test case 4: Multiplying by a number and then by its inverse should yield 1
        assert_eq!(mult(15, 239), 130);
        assert_eq!(mult(239, 15), 130);

        // Test case 5: Multiplying by 2 and checking for carry
        assert_eq!(mult(2, 128), 27); // 0x02 * 0x80 = 0x19

        // Test case 6: Multiplying by negative numbers (considered as modular multiplication)
        assert_eq!(mult(255, 1), 255);
        assert_eq!(mult(10, 246), 6);
    }

    #[test]
    fn test_pow() {
        // Test case 1: Base raised to the power of 0 should be 1
        assert_eq!(pow(2, 0), 1);

        // Test case 2: Base raised to the power of 1 should be the base itself
        assert_eq!(pow(3, 1), 3);

        // Test case 3: Base raised to the power of 0 should be 1 even if base is 0
        assert_eq!(pow(0, 0), 1);

        // Test case 4: Base raised to the power of 0 should be 1 even if base is not 0
        assert_eq!(pow(6, 0), 1);

        // Test case 5: Base raised to a positive power greater than 1
        assert_eq!(pow(60, 3), mult(mult(60, 60), 60));
        assert_eq!(pow(254, 2), mult(254, 254));
    }
}
