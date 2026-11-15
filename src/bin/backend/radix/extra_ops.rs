use super::{Digit, EncryptedValue, Lut, Radix};
use rayon::prelude::*;
use tfhe::core_crypto::prelude::*;
use tfhe_demo::expression::SCALE;

pub(super) struct DivisionLuts {
    nonzero: Lut,
    shift_two_low: Lut,
    shift_two_high: Lut,
}

impl DivisionLuts {
    pub(super) fn new(base: u64, lut: &impl Fn(&dyn Fn(u64) -> u64) -> Lut) -> Self {
        Self {
            nonzero: lut(&|value| u64::from(value != 0)),
            shift_two_low: lut(&|digit| 2 * digit % base),
            shift_two_high: lut(&|digit| 2 * digit / base),
        }
    }
}

impl Radix {
    pub fn subtract(&self, lhs: &EncryptedValue, rhs: &EncryptedValue) -> EncryptedValue {
        println!("[SUBTRACTION] Complement the right operand with lwe_ciphertext_sub_assign, then add with an initial encrypted carry of one.");
        let width = self.addition_width(lhs, rhs);
        let complement: Vec<_> = rhs.blocks[..width]
            .iter()
            .map(|digit| self.complement(digit))
            .collect();
        let (blocks, _) = self.add_blocks(&lhs.blocks[..width], &complement, self.constant(1));
        self.signed_value(blocks)
    }

    pub fn either_error(&self, mut left: Digit, right: &Digit) -> Digit {
        lwe_ciphertext_add_assign(&mut left, right);
        self.pbs(&left, &self.division.nonzero)
    }

    pub fn decrypt_error(
        &self,
        flag: &Digit,
        key: &LweSecretKeyOwned<u64>,
    ) -> Result<bool, String> {
        match self.decode(flag, key) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("Invalid encrypted error flag".into()),
        }
    }

    fn is_zero(&self, digits: &[Digit]) -> Digit {
        let mut flags: Vec<_> = digits
            .par_iter()
            .map(|digit| self.pbs(digit, &self.division.nonzero))
            .collect();
        while flags.len() > 1 {
            flags = flags
                .par_chunks(self.base as usize)
                .map(|chunk| {
                    let mut sum = chunk[0].clone();
                    for flag in &chunk[1..] {
                        lwe_ciphertext_add_assign(&mut sum, flag);
                    }
                    self.pbs(&sum, &self.division.nonzero)
                })
                .collect();
        }
        let mut zero = self.constant(1);
        lwe_ciphertext_sub_assign(&mut zero, &flags[0]);
        zero
    }

    pub fn divide(&self, lhs: &EncryptedValue, rhs: &EncryptedValue) -> (EncryptedValue, Digit) {
        println!("[DIVISION] Use an encrypted zero test and prepare the magnitudes.");
        let zero_flag = self.is_zero(&rhs.blocks[..rhs.width]);
        let ((left, left_sign), (right, right_sign)) =
            rayon::join(|| self.magnitude(lhs), || self.magnitude(rhs));

        let scale = SCALE as u128;
        let scale_digits: Vec<_> = (0..self.digits_for(scale))
            .map(|index| self.constant((scale >> (index * self.bits)) as u64 % self.base))
            .collect();
        println!("[DIVISION] Multiply the encrypted numerator by scale {SCALE}.");
        let numerator = self.multiply_magnitudes(&left, &scale_digits);
        let zero = self.constant(0);

        // A radix step brings down one base-four digit. Try 2*divisor, then divisor.
        let (doubled_low, doubled_high): (Vec<_>, Vec<_>) = right
            .par_iter()
            .map(|digit| {
                (
                    self.pbs(digit, &self.division.shift_two_low),
                    self.pbs(digit, &self.division.shift_two_high),
                )
            })
            .unzip();
        let doubled: Vec<_> = doubled_low
            .into_par_iter()
            .zip(
                std::iter::once(zero.clone())
                    .chain(doubled_high)
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .take(right.len()),
            )
            .map(|(mut low, high)| {
                lwe_ciphertext_add_assign(&mut low, &high);
                self.pbs(&low, &self.identity)
            })
            .collect();
        // The top digit of |rhs| is at most base/2, so doubling can require one extra digit.
        let mut twice = doubled;
        twice.push(self.pbs(
            right.last().expect("nonempty divisor"),
            &self.division.shift_two_high,
        ));
        let mut right = right;
        right.push(zero.clone());
        let (twice_complement, right_complement): (Vec<_>, Vec<_>) = twice
            .iter()
            .zip(&right)
            .map(|(high, low)| (self.complement(high), self.complement(low)))
            .unzip();
        let mut remainder = vec![zero; right.len()];
        let mut quotient = Vec::with_capacity(numerator.len());
        println!(
            "[DIVISION] Evaluate {} quotient steps with encrypted trial subtraction.",
            numerator.len()
        );
        for digit in numerator.into_iter().rev() {
            remainder.rotate_right(1);
            remainder[0] = digit;
            let (after_high, mut high) = self.divide_step(&remainder, &twice_complement);
            let (after_low, low) = self.divide_step(&after_high, &right_complement);
            remainder = after_low;
            lwe_ciphertext_cleartext_mul_assign(&mut high, Cleartext(2));
            lwe_ciphertext_add_assign(&mut high, &low);
            quotient.push(self.pbs(&high, &self.identity));
        }
        quotient.reverse();
        (
            self.signed_quotient(quotient, left_sign, &right_sign),
            zero_flag,
        )
    }

    fn divide_step(&self, remainder: &[Digit], complement: &[Digit]) -> (Vec<Digit>, Digit) {
        let (difference, no_borrow) = self.add_blocks(remainder, complement, self.constant(1));
        let next = difference
            .par_iter()
            .zip(remainder)
            .map(|(new, old)| self.select(&no_borrow, new, old))
            .collect();
        (next, no_borrow)
    }
}
