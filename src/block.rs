use super::*;
use std::ops::{Index, IndexMut};

/// Number of rows in a block matrix
pub const ROWS: usize = 4;

/// A basic AES block with a size of 128 bits
pub type Block = [u8; size::BLOCK];

/// Struct which allows indexing a block as a matrix
#[derive(Clone, Debug)]
pub struct BlockMatrix(pub Block);

impl BlockMatrix {
    /// Converts a (row, column) tuple to an array index
    #[inline]
    pub fn idx((row, col): (usize, usize)) -> usize {
        ROWS * col + row
    }

    /// Rotates a matrix row by 2 places
    pub fn shift_twice(&mut self, row: usize) {
        self.0.swap(Self::idx((row, 0)), Self::idx((row, 2)));
        self.0.swap(Self::idx((row, 1)), Self::idx((row, 3)));
    }

    /// Rotates a matrix row to the left by 1 place
    pub fn shift_left(&mut self, row: usize) {
        let temp = self[(row, 0)];
        self[(row, 0)] = self[(row, 1)];
        self[(row, 1)] = self[(row, 2)];
        self[(row, 2)] = self[(row, 3)];
        self[(row, 3)] = temp;
    }

    /// Rotates a matrix row to the right by 1 place
    pub fn shift_right(&mut self, row: usize) {
        let temp = self[(row, 3)];
        self[(row, 3)] = self[(row, 2)];
        self[(row, 2)] = self[(row, 1)];
        self[(row, 1)] = self[(row, 0)];
        self[(row, 0)] = temp;
    }

    /// AES shift rows operation
    pub fn shift_rows(mut self) -> Self {
        if cfg!(debug_assertions) {
            println!("Shift rows:");
            println!("Input: {self:x?}");
        }

        self.shift_left(1);
        self.shift_twice(2);
        self.shift_right(3);

        if cfg!(debug_assertions) {
            println!("Output: {self:x?}");
            println!("");
        }

        self
    }

    /// AES inverse shift rows operation
    pub fn inv_shift_rows(mut self) -> Self {
        if cfg!(debug_assertions) {
            println!("Inverse shift rows:");
            println!("Input: {self:x?}");
        }

        self.shift_right(1);
        self.shift_twice(2);
        self.shift_left(3);

        if cfg!(debug_assertions) {
            println!("Output: {self:x?}");
            println!("");
        }

        self
    }

    /// Multiples this matrix with another and returns the result
    pub fn mult(&self, rhs: &Self) -> Self {
        let mut output = Self([0; size::BLOCK]);

        for i in 0..ROWS {
            for j in 0..ROWS {
                for k in 0..ROWS {
                    output[(i, j)] ^= f256::mult(
                        self[(i, k)],
                        rhs[(k, j)]
                    );
                }
            }
        }

        output
    }

    /// AES mix columns operations
    pub fn mix_columns(self) -> Self {
        if cfg!(debug_assertions) {
            println!("Mix columns:");
            println!("Matrix: {self:x?}");
        }

        let mix = mix::FORWARD.mult(&self);

        if cfg!(debug_assertions) {
            println!("Output: {mix:x?}");
            println!("");
        }

        mix
    }

    /// AES inverse mix columns operations
    pub fn inv_mix_columns(self) -> Self {
        if cfg!(debug_assertions) {
            println!("Inverse mix columns:");
            println!("Matrix: {self:x?}");
        }

        let mix = mix::INVERSE.mult(&self);

        if cfg!(debug_assertions) {
            println!("Output: {mix:x?}");
            println!("");
        }

        mix
    }
}

// Allows indexing a block matrix using a (row, column) pair
impl Index<(usize, usize)> for BlockMatrix {
    type Output = u8;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        &self.0[Self::idx(index)]
    }
}

impl IndexMut<(usize, usize)> for BlockMatrix {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        &mut self.0[Self::idx(index)]
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;

    #[test]
    fn test_shift_rows() {
        let block: Block = array::from_fn(|i| i as u8);
        let result = BlockMatrix(block).shift_rows().0;

        let expected: Block = [
            0, 5, 10, 15,
            4, 9, 14, 3,
            8, 13, 2, 7,
            12, 1, 6, 11,
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_inv_shift_rows() {
        let block: Block = [
            0, 5, 10, 15,
            4, 9, 14, 3,
            8, 13, 2, 7,
            12, 1, 6, 11,
        ];

        let result = BlockMatrix(block).inv_shift_rows().0;
        let expected: Block = array::from_fn(|i| i as u8);

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

    #[test]
    fn test_inv_mix_columns() {
        // Case 1
        let block: Block = [
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
            0x8E, 0x4D, 0xA1, 0xBC,
        ];

        let expected: Block = [
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
            0xDB, 0x13, 0x53, 0x45,
        ];

        assert_eq!(BlockMatrix(block).inv_mix_columns().0, expected);

        // Case 2
        let block: Block = [
            0xBA, 0x75, 0xF4, 0x7A,
            0x84, 0xA4, 0x8D, 0x32,
            0xE8, 0x8D, 0x06, 0x0E,
            0x1B, 0x40, 0x7D, 0x5D
        ];

        let expected: Block = [
            0x63, 0x2F, 0xAF, 0xA2,
            0xEB, 0x93, 0xC7, 0x20,
            0x9F, 0x92, 0xAB, 0xCB,
            0xA0, 0xC0, 0x30, 0x2B,
        ];

        assert_eq!(BlockMatrix(block).inv_mix_columns().0, expected);
    }
}
