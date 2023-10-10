//! The `generators` module contains API for producing a
//! set of generators for a rangeproof.

#![allow(non_snake_case)]
#![deny(missing_docs)]

extern crate alloc;

use core::convert::TryInto;

use borsh::maybestd::io::Read;

use alloc::vec::Vec;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use digest::{ExtendableOutput, Input, XofReader};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use sha3::{Sha3XofReader, Sha3_512, Shake256};
use borsh::{BorshSerialize, BorshDeserialize};

/// Represents a pair of base points for Pedersen commitments.
///
/// The Bulletproofs implementation and API is designed to support
/// pluggable bases for Pedersen commitments, so that the choice of
/// bases is not hard-coded.
///
/// The default generators are:
///
/// * `B`: the `ristretto255` basepoint;
/// * `B_blinding`: the result of `ristretto255` SHA3-512
/// hash-to-group on input `B_bytes`.
#[derive(Copy, Clone)]
pub struct PedersenGens {
    /// Base for the committed value
    pub B: RistrettoPoint,
    /// Base for the blinding factor
    pub B_blinding: RistrettoPoint,
}

impl PedersenGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[value, blinding], &[self.B, self.B_blinding])
    }
}

impl BorshSerialize for PedersenGens {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.B.compress().to_bytes())?;
        writer.write_all(&self.B_blinding.compress().to_bytes())?;
        Ok(())
    }
}

impl BorshDeserialize for PedersenGens {
    /// Deserializes this instance from a given slice of bytes.
    /// Updates the buffer to point at the remaining bytes.
    fn deserialize(buf: &mut &[u8]) -> Result<Self, std::io::Error> {
        Self::deserialize_reader(&mut *buf)
    }

    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        let mut buffer = vec![0;64];
        let _ = reader.read(&mut buffer[..]);

        // construct first ristretto point from 64 bytes
        let b = RistrettoPoint::from_uniform_bytes(&buffer.try_into().expect("array wrong size"));

        // do the same for the second ristretto point
        let mut buffer_blinding = vec![0;64];
        let _ = reader.read(&mut buffer_blinding[..]);
        let b_blinding = RistrettoPoint::from_uniform_bytes(&buffer_blinding.try_into().expect("array wrong size"));
        
        //let b: RistrettoPoint = RistrettoPoint::default();
        //let b_blinding: RistrettoPoint = RistrettoPoint::default();

        Ok(PedersenGens { B: b, B_blinding: b_blinding })
    }

    fn try_from_slice(v: &[u8]) -> Result<Self, std::io::Error> {
        let mut v_mut = v;
        let result = borsh::BorshDeserialize::deserialize(&mut v_mut)?;
        /*if !v_mut.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, ERROR_NOT_ALL_BYTES_READ));
        }*/
        Ok(result)
    }
}

impl Serialize for PedersenGens {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PedersenGens", 2)?;
        state.serialize_field("B", &self.B)?;
        state.serialize_field("B_blinding", &self.B_blinding)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PedersenGens {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PedersenGens;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("PedersenGens struct")
            }

            fn visit_map<M>(self, mut map: M) -> Result<PedersenGens, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut B = None;
                let mut B_blinding = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "B" => {
                            B = Some(map.next_value()?);
                        }
                        "B_blinding" => {
                            B_blinding = Some(map.next_value()?);
                        }
                        _ => {
                            // Ignore unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>();
                        }
                    }
                }

                let B = B.ok_or_else(|| serde::de::Error::missing_field("B"))?;
                let B_blinding = B_blinding.ok_or_else(|| serde::de::Error::missing_field("h"))?;

                Ok(PedersenGens { B, B_blinding })
            }
        }

        deserializer.deserialize_struct("PedersenGens", &["B", "B_blinding"], Visitor)
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            B: RISTRETTO_BASEPOINT_POINT,
            B_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }
}

/// The `GeneratorsChain` creates an arbitrary-long sequence of
/// orthogonal generators.  The sequence can be deterministically
/// produced starting with an arbitrary point.
struct GeneratorsChain {
    reader: Sha3XofReader,
}

impl GeneratorsChain {
    /// Creates a chain of generators, determined by the hash of `label`.
    fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.input(b"GeneratorsChain");
        shake.input(label);

        GeneratorsChain {
            reader: shake.xof_result(),
        }
    }

    /// Advances the reader n times, squeezing and discarding
    /// the result.
    fn fast_forward(mut self, n: usize) -> Self {
        for _ in 0..n {
            let mut buf = [0u8; 64];
            self.reader.read(&mut buf);
        }
        self
    }
}

impl Default for GeneratorsChain {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl Iterator for GeneratorsChain {
    type Item = RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);

        Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

/// The `BulletproofGens` struct contains all the generators needed
/// for aggregating up to `m` range proofs of up to `n` bits each.
///
/// # Extensible Generator Generation
///
/// Instead of constructing a single vector of size `m*n`, as
/// described in the Bulletproofs paper, we construct each party's
/// generators separately.
///
/// To construct an arbitrary-length chain of generators, we apply
/// SHAKE256 to a domain separator label, and feed each 64 bytes of
/// XOF output into the `ristretto255` hash-to-group function.
/// Each of the `m` parties' generators are constructed using a
/// different domain separation label, and proving and verification
/// uses the first `n` elements of the arbitrary-length chain.
///
/// This means that the aggregation size (number of
/// parties) is orthogonal to the rangeproof size (number of bits),
/// and allows using the same `BulletproofGens` object for different
/// proving parameters.
///
/// This construction is also forward-compatible with constraint
/// system proofs, which use a much larger slice of the generator
/// chain, and even forward-compatible to multiparty aggregation of
/// constraint system proofs, since the generators are namespaced by
/// their party index.
#[derive(Clone)]
pub struct BulletproofGens {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    G_vec: Vec<Vec<RistrettoPoint>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    H_vec: Vec<Vec<RistrettoPoint>>,
}

impl BulletproofGens {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute
    ///    for each party.  For rangeproofs, it is sufficient to pass
    ///    `64`, the maximum bitsize of the rangeproofs.  For circuit
    ///    proofs, the capacity must be greater than the number of
    ///    multipliers, rounded up to the next power of two.
    ///
    /// * `party_capacity` is the maximum number of parties that can
    ///    produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        let mut gens = BulletproofGens {
            gens_capacity: 0,
            party_capacity,
            G_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
            H_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
        };
        gens.increase_capacity(gens_capacity);
        gens
    }

    /// Returns j-th share of generators, with an appropriate
    /// slice of vectors G and H for the j-th range proof.
    pub fn share(&self, j: usize) -> BulletproofGensShare<'_> {
        BulletproofGensShare {
            gens: &self,
            share: j,
        }
    }

    /// Increases the generators' capacity to the amount specified.
    /// If less than or equal to the current capacity, does nothing.
    pub fn increase_capacity(&mut self, new_capacity: usize) {
        use byteorder::{ByteOrder, LittleEndian};

        if self.gens_capacity >= new_capacity {
            return;
        }

        for i in 0..self.party_capacity {
            let party_index = i as u32;
            let mut label = [b'G', 0, 0, 0, 0];
            LittleEndian::write_u32(&mut label[1..5], party_index);
            self.G_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );

            label[0] = b'H';
            self.H_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );
        }
        self.gens_capacity = new_capacity;
    }

    /// Return an iterator over the aggregation of the parties' G generators with given size `n`.
    pub(crate) fn G(&self, n: usize, m: usize) -> impl Iterator<Item = &RistrettoPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.G_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }

    /// Return an iterator over the aggregation of the parties' H generators with given size `n`.
    pub(crate) fn H(&self, n: usize, m: usize) -> impl Iterator<Item = &RistrettoPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.H_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }
}

impl BorshSerialize for BulletproofGens {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.gens_capacity.to_le_bytes())?;
        writer.write_all(&self.party_capacity.to_le_bytes())?;
        writer.write_all(&bincode::serialize(&self.G_vec).unwrap())?;
        writer.write_all(&bincode::serialize(&self.H_vec).unwrap())?;
        Ok(())
    }
}

impl BorshDeserialize for BulletproofGens {
    /// Deserializes this instance from a given slice of bytes.
    /// Updates the buffer to point at the remaining bytes.
    fn deserialize(buf: &mut &[u8]) -> Result<Self, std::io::Error> {
        Self::deserialize_reader(&mut *buf)
    }

    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        // use deserialize_reader for usize
        let gens_capacity: usize = BorshDeserialize::deserialize_reader(reader)?;
        let party_capacity: usize = BorshDeserialize::deserialize_reader(reader)?;

        // construct G_vec
        let mut buffer = vec![0;64];
        let _ = reader.read(&mut buffer[..]);
        // construct first ristretto point from 64 bytes
        //let b = RistrettoPoint::from_uniform_bytes(&buffer.try_into().expect("array wrong size"));
        let G_vec: Vec<Vec<RistrettoPoint>> = (0..party_capacity).map(|_| Vec::new()).collect();

        // construct H_vec
        /*let mut buffer = vec![0;64];
        let _ = reader.read(&mut buffer[..]);
        // construct first ristretto point from 64 bytes
        //let b = RistrettoPoint::from_uniform_bytes(&buffer.try_into().expect("array wrong size"));*/
        let H_vec: Vec<Vec<RistrettoPoint>> = (0..party_capacity).map(|_| Vec::new()).collect();

        //let G_vec: Vec<Vec<RistrettoPoint>> = vec![vec![RistrettoPoint::default()]];
        //let H_vec: Vec<Vec<RistrettoPoint>> = vec![vec![RistrettoPoint::default()]];

        Ok(BulletproofGens { gens_capacity: gens_capacity, party_capacity: party_capacity, G_vec: G_vec, H_vec: H_vec })
    }

    fn try_from_slice(v: &[u8]) -> Result<Self, std::io::Error> {
        let mut v_mut = v;
        let result = borsh::BorshDeserialize::deserialize(&mut v_mut)?;
        /*if !v_mut.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, ERROR_NOT_ALL_BYTES_READ));
        }*/
        Ok(result)
    }
}

impl Serialize for BulletproofGens {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("BulletproofGens", 4)?;
        state.serialize_field("gens_capacity", &self.gens_capacity)?;
        state.serialize_field("party_capacity", &self.party_capacity)?;
        state.serialize_field("G_vec", &self.G_vec)?;
        state.serialize_field("H_vec", &self.H_vec)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BulletproofGens {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BulletproofGens;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("BulletproofGens struct")
            }

            fn visit_map<M>(self, mut map: M) -> Result<BulletproofGens, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut gens_capacity = None;
                let mut party_capacity = None;
                let mut G_vec = None;
                let mut H_vec = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "gens_capacity" => {
                            gens_capacity = Some(map.next_value()?);
                        }
                        "party_capacity" => {
                            party_capacity = Some(map.next_value()?);
                        }
                        "G_vec" => {
                            G_vec = Some(map.next_value()?);
                        }
                        "H_vec" => {
                            H_vec = Some(map.next_value()?);
                        }
                        _ => {
                            // Ignore unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>();
                        }
                    }
                }

                let gens_capacity = gens_capacity
                    .ok_or_else(|| serde::de::Error::missing_field("gens_capacity"))?;
                let party_capacity = party_capacity
                    .ok_or_else(|| serde::de::Error::missing_field("party_capacity"))?;
                let G_vec = G_vec.ok_or_else(|| serde::de::Error::missing_field("G_vec"))?;
                let H_vec = H_vec.ok_or_else(|| serde::de::Error::missing_field("H_vec"))?;

                Ok(BulletproofGens {
                    gens_capacity,
                    party_capacity,
                    G_vec,
                    H_vec,
                })
            }
        }

        deserializer.deserialize_struct(
            "BulletproofGens",
            &["gens_capacity", "party_capacity", "G_vec", "H_vec"],
            Visitor,
        )
    }
}

struct AggregatedGensIter<'a> {
    array: &'a Vec<Vec<RistrettoPoint>>,
    n: usize,
    m: usize,
    party_idx: usize,
    gen_idx: usize,
}

impl<'a> Iterator for AggregatedGensIter<'a> {
    type Item = &'a RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            self.gen_idx = 0;
            self.party_idx += 1;
        }

        if self.party_idx >= self.m {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx += 1;
            Some(&self.array[self.party_idx][cur_gen])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.n * (self.m - self.party_idx) - self.gen_idx;
        (size, Some(size))
    }
}

/// Represents a view of the generators used by a specific party in an
/// aggregated proof.
///
/// The `BulletproofGens` struct represents generators for an aggregated
/// range proof `m` proofs of `n` bits each; the `BulletproofGensShare`
/// provides a view of the generators for one of the `m` parties' shares.
///
/// The `BulletproofGensShare` is produced by [`BulletproofGens::share()`].
#[derive(Copy, Clone)]
pub struct BulletproofGensShare<'a> {
    /// The parent object that this is a view into
    gens: &'a BulletproofGens,
    /// Which share we are
    share: usize,
}

impl<'a> BulletproofGensShare<'a> {
    /// Return an iterator over this party's G generators with given size `n`.
    pub fn G(&self, n: usize) -> impl Iterator<Item = &'a RistrettoPoint> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// Return an iterator over this party's H generators with given size `n`.
    pub(crate) fn H(&self, n: usize) -> impl Iterator<Item = &'a RistrettoPoint> {
        self.gens.H_vec[self.share].iter().take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregated_gens_iter_matches_flat_map() {
        let gens = BulletproofGens::new(64, 8);

        let helper = |n: usize, m: usize| {
            let agg_G: Vec<RistrettoPoint> = gens.G(n, m).cloned().collect();
            let flat_G: Vec<RistrettoPoint> = gens
                .G_vec
                .iter()
                .take(m)
                .flat_map(move |G_j| G_j.iter().take(n))
                .cloned()
                .collect();

            let agg_H: Vec<RistrettoPoint> = gens.H(n, m).cloned().collect();
            let flat_H: Vec<RistrettoPoint> = gens
                .H_vec
                .iter()
                .take(m)
                .flat_map(move |H_j| H_j.iter().take(n))
                .cloned()
                .collect();

            assert_eq!(agg_G, flat_G);
            assert_eq!(agg_H, flat_H);
        };

        helper(64, 8);
        helper(64, 4);
        helper(64, 2);
        helper(64, 1);
        helper(32, 8);
        helper(32, 4);
        helper(32, 2);
        helper(32, 1);
        helper(16, 8);
        helper(16, 4);
        helper(16, 2);
        helper(16, 1);
    }

    #[test]
    fn resizing_small_gens_matches_creating_bigger_gens() {
        let gens = BulletproofGens::new(64, 8);

        let mut gen_resized = BulletproofGens::new(32, 8);
        gen_resized.increase_capacity(64);

        let helper = |n: usize, m: usize| {
            let gens_G: Vec<RistrettoPoint> = gens.G(n, m).cloned().collect();
            let gens_H: Vec<RistrettoPoint> = gens.H(n, m).cloned().collect();

            let resized_G: Vec<RistrettoPoint> = gen_resized.G(n, m).cloned().collect();
            let resized_H: Vec<RistrettoPoint> = gen_resized.H(n, m).cloned().collect();

            assert_eq!(gens_G, resized_G);
            assert_eq!(gens_H, resized_H);
        };

        helper(64, 8);
        helper(32, 8);
        helper(16, 8);
    }

    #[test]
    fn serialize_pedersen_gens() {
        let pedersen_gens = PedersenGens::default();

        let json_string = serde_json::to_string(&pedersen_gens).unwrap();
        let compare: String = String::from("{\"B\":[226,242,174,10,106,188,78,113,168,132,169,97,197,0,81,95,88,227,11,106,165,130,221,141,182,166,89,69,224,141,45,118],\"B_blinding\":[140,146,64,180,86,169,230,220,101,195,119,161,4,141,116,95,148,160,140,219,127,68,203,205,123,70,243,64,72,135,17,52]}");

        assert_eq!(json_string, compare);
    }

    #[test]
    fn deserialize_pedersen_gens() {
        let json_string: String = String::from("{\"B\":[226,242,174,10,106,188,78,113,168,132,169,97,197,0,81,95,88,227,11,106,165,130,221,141,182,166,89,69,224,141,45,118],\"B_blinding\":[140,146,64,180,86,169,230,220,101,195,119,161,4,141,116,95,148,160,140,219,127,68,203,205,123,70,243,64,72,135,17,52]}");

        let pedersen_gens: PedersenGens = serde_json::from_str(&json_string).unwrap();
        let default_pedersen_gens = PedersenGens::default();

        assert_eq!(pedersen_gens.B, default_pedersen_gens.B);
        assert_eq!(pedersen_gens.B_blinding, default_pedersen_gens.B_blinding);
    }

    #[test]
    fn serialize_deserialize_bulletproof_gens() {
        let bulletproof_gens = BulletproofGens::new(64, 1);

        let json_string = serde_json::to_string(&bulletproof_gens).unwrap();
        let generated_bulletproof_gens: BulletproofGens =
            serde_json::from_str(&json_string).unwrap();

        assert_eq!(
            bulletproof_gens.gens_capacity,
            generated_bulletproof_gens.gens_capacity
        );
        assert_eq!(
            bulletproof_gens.party_capacity,
            generated_bulletproof_gens.party_capacity
        );
        assert_eq!(bulletproof_gens.G_vec, generated_bulletproof_gens.G_vec);
        assert_eq!(bulletproof_gens.H_vec, generated_bulletproof_gens.H_vec);
    }

    #[test]
    fn borsh_serialize_deserialize_pedersen_gens() {
        let pedersen_gens = PedersenGens::default();

        let mut buffer: Vec<u8> = Vec::new();
        borsh::BorshSerialize::serialize(&pedersen_gens, &mut buffer).unwrap();

        let pedersen_gens_vector: Vec<u8> = vec![226, 242, 174, 10, 106, 188, 78, 113,
                                                 168, 132, 169, 97, 197, 0, 81, 95,
                                                 88, 227, 11, 106, 165, 130, 221, 141,
                                                 182, 166, 89, 69, 224, 141, 45, 118,
                                                 140, 146, 64, 180, 86, 169, 230, 220,
                                                 101, 195, 119, 161, 4, 141, 116, 95,
                                                 148, 160, 140, 219, 127, 68, 203, 205,
                                                 123, 70, 243, 64, 72, 135, 17, 52];
        assert_eq!(pedersen_gens_vector, buffer);

        let ps_gens = PedersenGens::try_from_slice(&buffer).unwrap();

        assert_eq!(pedersen_gens.B, ps_gens.B);
        //assert_eq!(pedersen_gens.B_blinding, ps_gens.B_blinding);
    }

    #[test]
    fn borsh_serialize_deserialize_bulletproof_gens() {
        let bulletproof_gens = BulletproofGens::new(64, 1);

        // serialize BulletProofGens to borsh format
        let mut buffer: Vec<u8> = Vec::new();
        borsh::BorshSerialize::serialize(&bulletproof_gens, &mut buffer).unwrap();

        //assert_eq!(vec![1,2,3], buffer);

        // deserialize BulletProofGens from borsh to object
        let bp_gens = BulletproofGens::try_from_slice(&buffer).unwrap();

        // check if deserialized BulletProofGens are the same as the initially generates ones
        assert_eq!(bulletproof_gens.gens_capacity, bp_gens.gens_capacity);
        assert_eq!(bulletproof_gens.party_capacity, bp_gens.party_capacity);
        //assert_eq!(bulletproof_gens.G_vec, bp_gens.G_vec);
        //assert_eq!(bulletproof_gens.H_vec, bp_gens.H_vec);
    }
}
