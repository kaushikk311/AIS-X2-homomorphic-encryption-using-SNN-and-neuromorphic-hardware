use std::cell::RefCell;
use std::cmp::Ordering;
use std::time::Instant;

use rayon::prelude::*;
use tfhe::core_crypto::algorithms::modulus_switch_noise_reduction::improve_lwe_ciphertext_modulus_switch_noise_for_binary_key;
use tfhe::core_crypto::prelude::*;
use tfhe::shortint::parameters::{
    ClassicPBSParameters, ModulusSwitchNoiseReductionParams, ModulusSwitchType,
};

use tfhe_demo::expression::{Comparison, MAX_INPUT, SCALE};

pub type Digit = LweCiphertextOwned<u64>;
type Lut = GlweCiphertextOwned<u64>;

thread_local! {
    static PBS_BUFFER: RefCell<ComputationBuffers> = RefCell::new(ComputationBuffers::new());
}

pub struct EncryptedValue {
    pub blocks: Vec<Digit>,
    // Public signed width bound in radix digits, derived from the input limit and AST.
    width: usize,
}

pub struct Radix {
    params: ClassicPBSParameters,
    pub base: u64,
    bits: usize,
    block_count: usize,
    delta: u64,
    bsk: FourierLweBootstrapKeyOwned,
    ksk: LweKeyswitchKeyOwned<u64>,
    drift: Option<(
        ModulusSwitchNoiseReductionParams,
        LweCiphertextListOwned<u64>,
    )>,
    fft: Fft,
    scratch_bytes: usize,
    identity: Lut,
    sum: Lut,
    carry: Lut,
    product_low: Lut,
    product_high: Lut,
    sign: Lut,
    keep_if_set: Lut,
    keep_if_clear: Lut,
    low_bit: Lut,
    high_bit: Lut,
    nonzero: Lut,
    digit_order: Lut,
    merge_order: Lut,
    bias_sign: Lut,
    shift_two_low: Lut,
    shift_two_high: Lut,
}

impl Radix {
    pub fn new(
        params: ClassicPBSParameters,
        bsk: FourierLweBootstrapKeyOwned,
        ksk: LweKeyswitchKeyOwned<u64>,
        small_key: &LweSecretKeyOwned<u64>,
        generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    ) -> Self {
        let base = params.message_modulus.0;
        let plaintext_modulus = base * params.carry_modulus.0;
        assert_eq!(base, 1 << 2, "This circuit uses two-bit radix digits");
        assert!(plaintext_modulus >= base * base);
        assert!(params.max_noise_level.get() >= base + 1);
        assert!(params.ciphertext_modulus.is_native_modulus());
        let bits = base.ilog2() as usize;
        let block_count = i128::BITS as usize / bits;
        let delta = (1u64 << (u64::BITS - 1)) / plaintext_modulus;
        let lut = |f: &dyn Fn(u64) -> u64| {
            generate_programmable_bootstrap_glwe_lut(
                params.polynomial_size,
                params.glwe_dimension.to_glwe_size(),
                plaintext_modulus as usize,
                params.ciphertext_modulus,
                delta,
                f,
            )
        };
        let drift = match params.modulus_switch_noise_reduction_params {
            ModulusSwitchType::DriftTechniqueNoiseReduction(config) => {
                let mut zeros = LweCiphertextList::new(
                    0,
                    small_key.lwe_dimension().to_lwe_size(),
                    config.modulus_switch_zeros_count,
                    params.ciphertext_modulus,
                );
                let plaintexts =
                    PlaintextList::new(0, PlaintextCount(config.modulus_switch_zeros_count.0));
                encrypt_lwe_ciphertext_list(
                    small_key,
                    &mut zeros,
                    &plaintexts,
                    params.lwe_noise_distribution,
                    generator,
                );
                Some((config, zeros))
            }
            _ => None,
        };
        let fft = Fft::new(params.polynomial_size);
        let scratch_bytes = blind_rotate_assign_mem_optimized_requirement::<u64>(
            bsk.glwe_size(),
            bsk.polynomial_size(),
            fft.as_view(),
        )
        .unaligned_bytes_required();

        Self {
            params,
            base,
            bits,
            block_count,
            delta,
            bsk,
            ksk,
            drift,
            fft,
            scratch_bytes,
            identity: lut(&|value| value),
            sum: lut(&|value| value % base),
            carry: lut(&|value| value / base),
            product_low: lut(&|pair| ((pair % base) * (pair / base)) % base),
            product_high: lut(&|pair| ((pair % base) * (pair / base)) / base),
            sign: lut(&|digit| u64::from(digit >= base / 2)),
            keep_if_set: lut(&|pair| (pair / 2) * (pair % 2)),
            keep_if_clear: lut(&|pair| (pair / 2) * (1 - pair % 2)),
            low_bit: lut(&|value| value % 2),
            high_bit: lut(&|value| (value / 2) % 2),
            nonzero: lut(&|value| u64::from(value != 0)),
            digit_order: lut(&|difference| match difference.cmp(&(base - 1)) {
                Ordering::Less => 0,
                Ordering::Equal => 1,
                Ordering::Greater => 2,
            }),
            merge_order: lut(&|pair| if pair / 3 == 1 { pair % 3 } else { pair / 3 }),
            bias_sign: lut(&|digit| (digit + base / 2) % base),
            shift_two_low: lut(&|digit| 2 * digit % base),
            shift_two_high: lut(&|digit| 2 * digit / base),
        }
    }

    fn pbs(&self, input: &Digit, lut: &Lut) -> Digit {
        let mut accumulator = lut.clone();
        let log_modulus = self
            .params
            .polynomial_size
            .to_blind_rotation_input_modulus_log();
        let mut corrected;
        let switched = match self.params.modulus_switch_noise_reduction_params {
            ModulusSwitchType::CenteredMeanNoiseReduction => {
                lwe_ciphertext_centered_binary_modulus_switch(input.as_view(), log_modulus)
            }
            ModulusSwitchType::DriftTechniqueNoiseReduction(_) => {
                let (config, zeros) = self.drift.as_ref().expect("missing noise reduction key");
                corrected = input.clone();
                improve_lwe_ciphertext_modulus_switch_noise_for_binary_key(
                    &mut corrected,
                    zeros,
                    config.ms_r_sigma_factor,
                    config.ms_bound,
                    config.ms_input_variance,
                    log_modulus,
                );
                lwe_ciphertext_modulus_switch(corrected.as_view(), log_modulus)
            }
            ModulusSwitchType::Standard => {
                lwe_ciphertext_modulus_switch(input.as_view(), log_modulus)
            }
        };
        PBS_BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.resize(self.scratch_bytes);
            blind_rotate_assign_mem_optimized(
                &switched,
                &mut accumulator,
                &self.bsk,
                self.fft.as_view(),
                buffer.stack(),
            );
        });
        let mut large = LweCiphertext::new(
            0,
            self.ksk.input_key_lwe_dimension().to_lwe_size(),
            self.params.ciphertext_modulus,
        );
        extract_lwe_sample_from_glwe_ciphertext(&accumulator, &mut large, MonomialDegree(0));
        let mut small = self.constant(0);
        keyswitch_lwe_ciphertext(&self.ksk, &large, &mut small);
        small
    }

    fn constant(&self, digit: u64) -> Digit {
        allocate_and_trivially_encrypt_new_lwe_ciphertext(
            self.params.lwe_dimension.to_lwe_size(),
            Plaintext(digit * self.delta),
            self.params.ciphertext_modulus,
        )
    }

    pub fn either_error(&self, mut left: Digit, right: &Digit) -> Digit {
        lwe_ciphertext_add_assign(&mut left, right);
        self.pbs(&left, &self.nonzero)
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

    fn decode(&self, block: &Digit, key: &LweSecretKeyOwned<u64>) -> u64 {
        let phase = decrypt_lwe_ciphertext(key, block).0;
        phase.wrapping_add(self.delta / 2) / self.delta
    }

    fn digits_for(&self, value: u128) -> usize {
        ((u128::BITS - value.leading_zeros()) as usize).div_ceil(self.bits)
    }

    pub fn encrypt(
        &self,
        value: i128,
        key: &LweSecretKeyOwned<u64>,
        generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    ) -> EncryptedValue {
        let start = Instant::now();
        let bits = value as u128;
        let fresh: Vec<_> = (0..self.block_count)
            .map(|index| {
                let digit = (bits >> (index * self.bits)) as u64 % self.base;
                allocate_and_encrypt_new_lwe_ciphertext(
                    key,
                    Plaintext(digit * self.delta),
                    self.params.lwe_noise_distribution,
                    self.params.ciphertext_modulus,
                    generator,
                )
            })
            .collect();
        println!(
            "[ENCRYPT] {} radix blocks in {:?}",
            fresh.len(),
            start.elapsed()
        );
        let start = Instant::now();
        let blocks = fresh
            .par_iter()
            .map(|digit| self.pbs(digit, &self.identity))
            .collect();
        println!("[PBS/KS] Refreshed literal in {:?}", start.elapsed());
        EncryptedValue {
            blocks,
            width: self.digits_for((MAX_INPUT as u128) << 1),
        }
    }

    pub fn decrypt(
        &self,
        value: &EncryptedValue,
        key: &LweSecretKeyOwned<u64>,
    ) -> Result<i128, String> {
        let mut result = 0u128;
        for (index, block) in value.blocks.iter().enumerate() {
            let digit = self.decode(block, key);
            if digit >= self.base {
                return Err(format!("Invalid radix digit in final result block {index}"));
            }
            result |= (digit as u128) << (index * self.bits);
        }
        Ok(result as i128)
    }

    fn signed_value(&self, mut blocks: Vec<Digit>) -> EncryptedValue {
        let width = blocks.len();
        if width < self.block_count {
            // A sign-extension digit is either zero or all ones in base four.
            let sign = self.pbs(blocks.last().expect("nonempty signed value"), &self.sign);
            let mut extension = sign;
            lwe_ciphertext_cleartext_mul_assign(&mut extension, Cleartext(self.base - 1));
            let extension = self.pbs(&extension, &self.identity);
            blocks.resize(self.block_count, extension);
        }
        EncryptedValue { blocks, width }
    }

    fn add_blocks(&self, lhs: &[Digit], rhs: &[Digit], mut carry: Digit) -> (Vec<Digit>, Digit) {
        let totals: Vec<_> = lhs
            .iter()
            .zip(rhs)
            .map(|(left, right)| {
                let mut total = left.clone();
                lwe_ciphertext_add_assign(&mut total, right);
                lwe_ciphertext_add_assign(&mut total, &carry);
                carry = self.pbs(&total, &self.carry);
                total
            })
            .collect();
        let digits = totals
            .par_iter()
            .map(|total| self.pbs(total, &self.sum))
            .collect();
        (digits, carry)
    }

    fn complement(&self, digit: &Digit) -> Digit {
        let mut out = self.constant(self.base - 1);
        lwe_ciphertext_sub_assign(&mut out, digit);
        out
    }

    pub fn add(
        &self,
        lhs: &EncryptedValue,
        rhs: &EncryptedValue,
        subtract: bool,
    ) -> EncryptedValue {
        let width = (lhs.width.max(rhs.width) + 1).min(self.block_count);
        let left = &lhs.blocks[..width];
        let right = &rhs.blocks[..width];
        let (blocks, _) = if subtract {
            let complement: Vec<_> = right.iter().map(|digit| self.complement(digit)).collect();
            self.add_blocks(left, &complement, self.constant(1))
        } else {
            self.add_blocks(left, right, self.constant(0))
        };
        self.signed_value(blocks)
    }

    fn negate_blocks(&self, digits: &[Digit]) -> Vec<Digit> {
        let mut carry = self.constant(1);
        digits
            .iter()
            .map(|digit| {
                let mut total = self.complement(digit);
                lwe_ciphertext_add_assign(&mut total, &carry);
                let digit = self.pbs(&total, &self.sum);
                carry = self.pbs(&total, &self.carry);
                digit
            })
            .collect()
    }

    pub fn negate(&self, value: &EncryptedValue) -> EncryptedValue {
        let width = (value.width + 1).min(self.block_count);
        self.signed_value(self.negate_blocks(&value.blocks[..width]))
    }

    fn select(&self, flag: &Digit, when_set: &Digit, when_clear: &Digit) -> Digit {
        let gate = |digit: &Digit, lut: &Lut| {
            let mut pair = digit.clone();
            lwe_ciphertext_cleartext_mul_assign(&mut pair, Cleartext(2));
            lwe_ciphertext_add_assign(&mut pair, flag);
            self.pbs(&pair, lut)
        };
        let mut output = gate(when_set, &self.keep_if_set);
        lwe_ciphertext_add_assign(&mut output, &gate(when_clear, &self.keep_if_clear));
        self.pbs(&output, &self.identity)
    }

    fn conditional_negate(&self, digits: &[Digit], sign: &Digit) -> Vec<Digit> {
        let negative = self.negate_blocks(digits);
        digits
            .par_iter()
            .zip(&negative)
            .map(|(positive, negative)| self.select(sign, negative, positive))
            .collect()
    }

    fn magnitude(&self, value: &EncryptedValue) -> (Vec<Digit>, Digit) {
        let digits = &value.blocks[..value.width];
        let sign = self.pbs(digits.last().expect("nonempty signed value"), &self.sign);
        (self.conditional_negate(digits, &sign), sign)
    }

    pub fn compare(
        &self,
        lhs: &EncryptedValue,
        rhs: &EncryptedValue,
        op: Comparison,
    ) -> EncryptedValue {
        let width = lhs.width.max(rhs.width);
        // Reversing the sign bit on the most significant digit makes unsigned order signed.
        let mut orders: Vec<_> = (0..width)
            .into_par_iter()
            .map(|index| {
                let (mut left, right) = if index + 1 == width {
                    (
                        self.pbs(&lhs.blocks[index], &self.bias_sign),
                        self.pbs(&rhs.blocks[index], &self.bias_sign),
                    )
                } else {
                    (lhs.blocks[index].clone(), rhs.blocks[index].clone())
                };
                lwe_ciphertext_sub_assign(&mut left, &right);
                lwe_ciphertext_plaintext_add_assign(
                    &mut left,
                    Plaintext((self.base - 1) * self.delta),
                );
                self.pbs(&left, &self.digit_order)
            })
            .collect();
        // The most significant unequal digit determines the ordering.
        while orders.len() > 1 {
            orders = orders
                .par_chunks(2)
                .map(|pair| {
                    let [lower, upper] = pair else {
                        return pair[0].clone();
                    };
                    let mut packed = upper.clone();
                    lwe_ciphertext_cleartext_mul_assign(&mut packed, Cleartext(3));
                    lwe_ciphertext_add_assign(&mut packed, lower);
                    self.pbs(&packed, &self.merge_order)
                })
                .collect();
        }
        // Encode the encrypted boolean as a fixed-point 0 or 1.
        let width = self.digits_for((SCALE as u128) << 1);
        let blocks = (0..width)
            .into_par_iter()
            .map(|index| {
                let digit = ((SCALE as u128) >> (index * self.bits)) as u64 % self.base;
                if digit == 0 {
                    return self.constant(0);
                }
                let lut = generate_programmable_bootstrap_glwe_lut(
                    self.params.polynomial_size,
                    self.params.glwe_dimension.to_glwe_size(),
                    (self.base * self.params.carry_modulus.0) as usize,
                    self.params.ciphertext_modulus,
                    self.delta,
                    |code| digit * u64::from(op.matches(code.cmp(&1))),
                );
                self.pbs(&orders[0], &lut)
            })
            .collect();
        self.signed_value(blocks)
    }

    fn is_zero(&self, digits: &[Digit]) -> Digit {
        let mut flags: Vec<_> = digits
            .par_iter()
            .map(|digit| self.pbs(digit, &self.nonzero))
            .collect();
        while flags.len() > 1 {
            flags = flags
                .par_chunks(self.base as usize)
                .map(|chunk| {
                    let mut sum = chunk[0].clone();
                    for flag in &chunk[1..] {
                        lwe_ciphertext_add_assign(&mut sum, flag);
                    }
                    self.pbs(&sum, &self.nonzero)
                })
                .collect();
        }
        let mut zero = self.constant(1);
        lwe_ciphertext_sub_assign(&mut zero, &flags[0]);
        zero
    }

    pub fn divide(&self, lhs: &EncryptedValue, rhs: &EncryptedValue) -> (EncryptedValue, Digit) {
        let zero_flag = self.is_zero(&rhs.blocks[..rhs.width]);
        let ((left, left_sign), (right, right_sign)) =
            rayon::join(|| self.magnitude(lhs), || self.magnitude(rhs));

        let scale = SCALE as u128;
        let scale_digits: Vec<_> = (0..self.digits_for(scale))
            .map(|index| self.constant((scale >> (index * self.bits)) as u64 % self.base))
            .collect();
        let numerator = self.multiply_magnitudes(&left, &scale_digits);
        let zero = self.constant(0);

        // A radix step brings down one base-four digit. Try 2*divisor, then divisor.
        let (doubled_low, doubled_high): (Vec<_>, Vec<_>) = right
            .par_iter()
            .map(|digit| {
                (
                    self.pbs(digit, &self.shift_two_low),
                    self.pbs(digit, &self.shift_two_high),
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
            &self.shift_two_high,
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

    fn signed_quotient(
        &self,
        mut digits: Vec<Digit>,
        mut left_sign: Digit,
        right_sign: &Digit,
    ) -> EncryptedValue {
        lwe_ciphertext_add_assign(&mut left_sign, right_sign);
        let sign = self.pbs(&left_sign, &self.low_bit);
        if digits.len() < self.block_count {
            digits.push(self.constant(0));
        }
        digits.truncate(self.block_count);
        self.signed_value(self.conditional_negate(&digits, &sign))
    }

    fn digit_product(&self, left: &Digit, right: &Digit) -> (Digit, Digit) {
        let mut pair = right.clone();
        lwe_ciphertext_cleartext_mul_assign(&mut pair, Cleartext(self.base));
        lwe_ciphertext_add_assign(&mut pair, left);
        (
            self.pbs(&pair, &self.product_low),
            self.pbs(&pair, &self.product_high),
        )
    }

    fn multiply_magnitudes(&self, lhs: &[Digit], rhs: &[Digit]) -> Vec<Digit> {
        let width = lhs.len() + rhs.len();
        let zero = self.constant(0);
        let mut rows: Vec<_> = rhs
            .par_iter()
            .enumerate()
            .flat_map_iter(|(offset, right)| {
                // Empty slots are public zeros determined only by the row's position.
                let mut low = vec![None; width];
                let mut high = low.clone();
                for (index, left) in lhs.iter().enumerate() {
                    let (digit, carry) = self.digit_product(left, right);
                    low[offset + index] = Some(digit);
                    high[offset + index + 1] = Some(carry);
                }
                [low, high]
            })
            .collect();

        // Reduce three rows to a digit row and a shifted carry row without a ripple.
        while rows.len() > 2 {
            let reduced = rows
                .par_chunks(3)
                .map(|group| {
                    let [first, second, third] = group else {
                        return group.to_vec();
                    };
                    let mut sum = Vec::with_capacity(width);
                    let mut carry = vec![None; width];
                    for index in 0..width {
                        let mut digits = [&first[index], &second[index], &third[index]]
                            .into_iter()
                            .flatten();
                        match (digits.next(), digits.next()) {
                            (None, _) => sum.push(None),
                            (Some(digit), None) => sum.push(Some(digit.clone())),
                            (Some(left), Some(right)) => {
                                let mut total = left.clone();
                                lwe_ciphertext_add_assign(&mut total, right);
                                if let Some(third) = digits.next() {
                                    lwe_ciphertext_add_assign(&mut total, third);
                                }
                                sum.push(Some(self.pbs(&total, &self.sum)));
                                if index + 1 < width {
                                    carry[index + 1] = Some(self.pbs(&total, &self.carry));
                                }
                            }
                        }
                    }
                    vec![sum, carry]
                })
                .collect::<Vec<_>>();
            rows = reduced.into_iter().flatten().collect();
        }
        let mut rows = rows.into_iter().map(|row| {
            row.into_iter()
                .map(|digit| digit.unwrap_or_else(|| zero.clone()))
                .collect::<Vec<_>>()
        });
        let left = rows.next().expect("low product row");
        let right = rows.next().expect("high product row");
        self.add_blocks(&left, &right, zero).0
    }

    fn subtract_constant(&self, digits: &[Digit], divisor: u128) -> (Vec<Digit>, Digit) {
        // Compute remainder - divisor via base complement; the final carry means no borrow.
        let mut no_borrow = self.constant(1);
        let totals: Vec<_> = digits
            .iter()
            .enumerate()
            .map(|(index, digit)| {
                let divisor_digit = (divisor >> (index * self.bits)) as u64 % self.base;
                let mut total = digit.clone();
                lwe_ciphertext_plaintext_add_assign(
                    &mut total,
                    Plaintext((self.base - 1 - divisor_digit) * self.delta),
                );
                lwe_ciphertext_add_assign(&mut total, &no_borrow);
                no_borrow = self.pbs(&total, &self.carry);
                total
            })
            .collect();
        let remainder = totals
            .par_iter()
            .zip(digits)
            .map(|(total, old)| {
                let new = self.pbs(total, &self.sum);
                self.select(&no_borrow, &new, old)
            })
            .collect();
        (remainder, no_borrow)
    }

    fn shift_right(&self, digits: &[Digit], bits: usize) -> Vec<Digit> {
        let whole = bits / self.bits;
        if whole >= digits.len() {
            return vec![self.constant(0)];
        }
        let digits = &digits[whole..];
        if bits.is_multiple_of(self.bits) {
            return digits.to_vec();
        }
        // Each digit contributes its high bit and the next digit contributes its low bit.
        (0..digits.len())
            .into_par_iter()
            .map(|index| {
                let mut digit = self.pbs(&digits[index], &self.high_bit);
                if let Some(next) = digits.get(index + 1) {
                    let mut upper = self.pbs(next, &self.low_bit);
                    lwe_ciphertext_cleartext_mul_assign(&mut upper, Cleartext(2));
                    lwe_ciphertext_add_assign(&mut digit, &upper);
                }
                self.pbs(&digit, &self.identity)
            })
            .collect()
    }

    fn rescale(&self, product: &[Digit]) -> Vec<Digit> {
        let scale = SCALE as u128;
        let shift = scale.trailing_zeros() as usize;
        let divisor = scale >> shift;
        let product = self.shift_right(product, shift);
        let divisor_width = self.digits_for(divisor);
        if product.len() < divisor_width {
            return vec![self.constant(0)];
        }
        let remainder_width = self.digits_for(self.base as u128 * divisor - 1);
        let mut remainder = vec![self.constant(0); remainder_width];
        let mut quotient = Vec::with_capacity(product.len() - divisor_width + 1);

        for (index, digit) in product.into_iter().rev().enumerate() {
            remainder.rotate_right(1);
            remainder[0] = digit;
            if index + 1 < divisor_width {
                continue;
            }
            let (after_high, mut high) = self.subtract_constant(&remainder, divisor * 2);
            let (after_low, low) = self.subtract_constant(&after_high, divisor);
            remainder = after_low;
            lwe_ciphertext_cleartext_mul_assign(&mut high, Cleartext(2));
            lwe_ciphertext_add_assign(&mut high, &low);
            quotient.push(self.pbs(&high, &self.identity));
        }
        quotient.reverse();
        quotient
    }

    pub fn multiply(&self, lhs: &EncryptedValue, rhs: &EncryptedValue) -> EncryptedValue {
        let ((left, left_sign), (right, right_sign)) =
            rayon::join(|| self.magnitude(lhs), || self.magnitude(rhs));
        let start = Instant::now();
        let product = self.multiply_magnitudes(&left, &right);
        println!(
            "[MUL/PBS/KS] Partial products and carry reduction: {:?}",
            start.elapsed()
        );
        let start = Instant::now();
        let scaled = self.rescale(&product);
        println!(
            "[RESCALE/PBS/KS] Encrypted division by {SCALE}: {:?}",
            start.elapsed()
        );

        self.signed_quotient(scaled, left_sign, &right_sign)
    }
}
