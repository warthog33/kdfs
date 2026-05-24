//pub mod hash_encrypt;

use std::iter::once;
use std::ops::{Add, AddAssign, Mul};

//use generic_array::{GenericArray, ArrayLength};
pub extern crate hybrid_array;
use hybrid_array::{Array, ArraySize};
use num_traits::{One, ToBytes, Zero};

//use digest::XofReader;

pub trait InitSalt {
    fn new_with_salt ( salt: &[u8] ) -> Self;
}
pub trait GetExtract {
    type T;
    fn get_extract(&self) -> &Self::T;
}
pub trait GetExpand {
    type T;
    fn get_expand(&self) -> &Self::T;
}
  
#[derive(Debug)]
pub enum Error {
    InvalidBufferSize,
    InvalidLength,
}

impl From<digest::InvalidLength> for Error {
    fn from(_value: digest::InvalidLength) -> Self {
        return Error::InvalidLength;
    }
}

pub trait Kdf {
    /// Derive function with support for multiple secrets and multiple other fields. Writes into a buffer
    fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error>;

    /// Derive function with multiple secrets and a single other field. Writes into a buffer
    fn derive_self_secrets_other_into<'a> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other: &[u8], out: &mut [u8]) -> Result<(), Error>
    {
        Self::derive_self_secrets_others_into(self, secret, [other], out)
    }
    /// Derive function which accepts a single secret slice, and multiple other_data slices
    fn derive_self_secret_others_into<'a> (& self, secret: &[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone, out: &mut [u8]) -> Result<(), Error>
    {
        self.derive_self_secrets_others_into(once(secret), other_data, out)
    }
    /// Derive function with multiple secrets and a multiple other fields. Returns an Array
    fn derive_self_secrets_others<'a,'b,L: ArraySize> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Result<Array<u8,L>, Error> where Self: Sized
    { 
        let mut out = Array::default();
        self.derive_self_secrets_others_into ( secrets, other_data, &mut out)?;
        Ok(out)
    }
    /// Derive function with single input secret and support for multiple other fields Returns an Array
    fn derive_self_secret_others<'a, L: ArraySize> ( &self, secret: &'a[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> Result<Array<u8,L>,Error> 
        where Self: Sized 
    { 
        let mut out = Array::default();
        self.derive_self_secret_others_into(secret, other_data, &mut out)?;
        Ok(out)
    }
    /// Derive function with single input secret and support for multiple other fields Returns an Array
    fn derive_self_secret_other<L: ArraySize> ( &self, secret: &[u8], other_data: &[u8]) -> Result<Array<u8,L>, Error> 
        where Self: Sized/*where Self: OutputSizeUser + Sized*/ 
    {
        self.derive_self_secret_others(secret, once(other_data))
    }
    /// Derive function with support for multiple input secrets and a single other field. Returns an Array
    fn derive_self_secrets_other<'a,L: ArraySize> (&self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other: &[u8]) -> Array<u8,L> 
    where Self: Sized {
        let mut out = Array::default();
        self.derive_self_secrets_other_into(secrets, other, &mut out).unwrap();
        out
    }

    /// Derive function with support for multiple input secrets and multiple other fields. Returns an Array
    fn derive_secrets_others<'a, 'c: 'a, L: ArraySize> ( secrets: impl IntoIterator<Item=&'c[u8]> + Clone, other_data: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>, Error> where Self: Default {
        Self::default().derive_self_secrets_others(secrets, other_data)
    }
    /// Derive function with support for single secret slice and multiple other fields. Returns an Array
    fn derive_secret_others<'a, L:ArraySize> ( secret: &'a[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> Result<Array<u8,L>, Error>
     where Self: Default { 
        return Self::default().derive_self_secret_others(secret, other_data);
    }
    /// Derive function which accepts a single secrets and a single other field. Returns an Array
    fn derive_secret_other<'a, 'c:'a, L: ArraySize> ( secret: &'a[u8], other: &[u8]) -> Result<Array<u8,L>, Error>
     where Self: Default /*OutputSizeUser + Default*/{
        return Self::default().derive_self_secret_other(secret, other);
    }
    /// Derive function with support for multiple input secrets and a single other field. Returns an Array
    fn derive_secrets_other<'a, 'c:'a, L: ArraySize> ( secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other: &'a[u8]) -> Array<u8,L> where Self: Default /*OutputSizeUser + Default*/{
        return Self::default().derive_self_secrets_other(secrets, other);
    }

    // functions without self, but with salt
    /// Derive function with support for multiple secrets, a salt and multiple other fields. Returns an Array
    fn derive_secrets_salt_others<'a,'b, L: ArraySize> ( secrets: impl IntoIterator<Item=&'a[u8]> + Clone, salt: &[u8], other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Result<Array<u8,L>, Error>
        where Self: Default + InitSalt
    { 
        Self::derive_self_secrets_others(&Self::new_with_salt(salt), secrets, other_data)
    }
    /// Derive function with support for a single secret, a salt and multiple other fields. Returns an Array
    fn derive_secret_salt_others<'a, L:ArraySize> ( secret: &[u8], salt: &[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> Result<Array<u8,L>, Error>
        where Self: Default + InitSalt 
    { 
        Self::derive_secrets_salt_others(once(secret), salt, other_data)
    }
    /// Derive function with support for a single secret, a salt and single other field. Returns an Array
    fn derive_secret_salt_other<'a, L: ArraySize> ( secret: &'a [u8], salt: &'a[u8], infos: &[u8]) -> Result<Array<u8, L>, Error> 
        where Self: Default + InitSalt 
    {
       Self::derive_secret_salt_others(secret, salt, once(infos))
    }
    /// Derive function with support for a single secrets and a salt. Returns an Array
    fn derive_salt_secret<'a, 'c: 'a, L:ArraySize>( salt: &'c[u8], secret: &'c[u8]) -> Result<Array<u8,L>, Error>
        where Self: Kdf + Default + InitSalt 
    {
        <Self as Kdf>::derive_secret_salt_others(secret, salt, None)
    }
}



///
/// A KDF which has a nominal output size, important for two step KDFs as the size is used
/// 
pub trait KdfFixed: Kdf {
    type OutputSize: ArraySize;
}

/// Trait representing a const label
pub trait Label {
    const LABEL: &'static[u8];
}


pub trait KdfLabelled: Kdf {
    fn new_with_label<L: Label>() -> Self; // 
    //fn new_with_label ( label: &'static[u8]) -> Self;

    fn derive_self_secret_label_other<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: &'c[u8]) -> Result<Array<u8,L>,Error>
    {
        self.derive_self_secret_label_others (secret, label, once(other))
    }
    fn derive_self_secret_label_others<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error>
    {
        self.derive_self_secrets_label_others (once(secret), label, others)
    }
    fn derive_self_secrets_label_others<'a, 'b: 'a, 'c: 'a, L:ArraySize> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error>
    {
        let mut out = Array::<u8, L>::default();
        self.derive_self_secrets_label_others_into(secrets, label, others,&mut out)?;
        Ok(out)
    }
    fn derive_self_secrets_label_others_into<'a, 'b, 'c> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone, out: &mut[u8]) -> Result<(),Error>;

}

///
/// A trait representing a KDF which is composed to two individual KDFs
/// This architecture is described in ISO 17770-3 and is used by HKDF
/// 
pub trait TwoStepKdf
{
    /// The extract step takes the entropy from the inputs and compresses it to a fixed size output. 
    /// The salt can be used to diversity the output 
    type Extract: KdfFixed + InitSalt + Default;
    /// The expand step takes as an input the output from the extract stage and produces an output of
    /// any desired length. Diversification inputs are necessary to ensure different keys/secrets created
    /// from the same extracted value are different
    type Expand: Kdf + Default;
}




/// Key derivation described in ISO 11770-6. This document contains a large number of key derivation functions with many
/// options. Many other KDFs are effectively sub-types of KDFs described in this document
pub mod iso11770_6;

/// Other kdfs, including the KDF described by EMV and KDFs based on extensible output functions
pub mod misc;



/// Key derivations functions described in ISO 18033-2, which is for asymmetric encryption
pub mod iso18033_2 {
    /// Variant of Okdf5 with a counter starting at 0
    pub type Kdf1<D> = crate::iso11770_6::Okdf5<D,0>;
    /// Variant of Okdf5 with a counter starting at 1
    pub type Kdf2<D> = crate::iso11770_6::Okdf5<D,1>;
}


/// KDFs listed or referenced from ANSI X9.42
pub mod ansi_x9_42 {
    /// KDF defined in ANSI X9.42:2003, section 7.7.1.
    /// It is designed for use with ASN.1 formatted fields, which are not captured in the main API.
    /// It is a specialisation of the ISO 118770-6 Okdf2 KDF with a 32 bit counter
    /// kdasn1der OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi -x942(10046) kdMethods(5) asn1der(0) }
    pub type X942Asn1Kdf<'a, H> = crate::iso11770_6::Okdf2<'a, H, u32>;
    
    /// KDF defined in ANSI X9.42:2003, section 7.7.2
    /// Concatenation style KDF which performs a hash calculation over the concatenated input fields. The loop counter is 32 bits
    /// kdConcatenation OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) ansi-x942(10046) kdMethods(5) concatenation(1) }
    pub type X942KdfConcat<H> = super::ansi_x9_63::X963Kdf<H>; // According to openssl this is the same alg as X9.63 kdf
    
}

/// KDFs listed or referenced from ANSI X9.44
pub mod ansi_x9_44 {
    /// KDF defined in ANSI X9.44, same as X9.63 Kdf
    /// kdf2 ALGORITHM ::= { OID iso(1) identified-organization(3) tc68(133) country(16) x9(840) x9Standards(9) x9-44(44) components(1) kdf2(1) PARMS X9-HashFunction }
    pub type X944Kdf2<H> = super::ansi_x9_63::X963Kdf<H>;

    /// KDF defined in ANSI X9.44, same as Okdf3
    /// kdf3 ALGORITHM ::= { OID iso(1) identified-organization(3) tc68(133) country(16) x9(840) x9Standards(9) x9-44(44) components(1) kdf3(2) PARMS X9-HashFunction }
    pub type X944Kdf3<H> = crate::iso11770_6::Okdf3<H, u32>;
}

/// KDFS described in ANSI X9.63. X9.63 is focused on the use of elliptic curve for key agreement, which requires a suitable KDF to output symmetric keys
///  ansi-X9-63 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) tc68(133) country(16) x9(840) x9Standards(9) x9-63(63) }
pub mod ansi_x9_63 {
    /// The X9.63 KDF is a type of Okdf4 with a 32-bit counter
    pub type X963Kdf<H> = crate::iso11770_6::Okdf4<H,u32>;

    /// X9.63 KDF using RustCrypto Sha1
    #[cfg(feature="rustcrypto-sha1")]
    pub type X963KdfSha1 = X963Kdf<sha1::Sha1>;

    /// X9.63 KDF using RustCrypto Sha224
    #[cfg(feature="rustcrypto-sha2")]
    pub type X963KdfSha224 = X963Kdf<sha2::Sha224>;
    
    /// X9.63 KDF using RustCrypto Sha256
    #[cfg(feature="rustcrypto-sha2")]
    pub type X963KdfSha256 = X963Kdf<sha2::Sha256>;

    /// X9.63 KDF using RustCrypto Sha384
    #[cfg(feature="rustcrypto-sha2")]
    pub type X963KdfSha384 = X963Kdf<sha2::Sha384>;

    /// X9.63 KDF using RustCrypto Sha512
    #[cfg(feature="rustcrypto-sha2")]
    pub type X963KdfSha512 = X963Kdf<sha2::Sha512>;
   
}

/// Key derivation functions were initially in SP800-56A, they are now located in 
/// SP800-56C
pub mod nistsp800_56 {
    // Concat Key Derivation Function, from original version of NIST SP800-56A
    pub type ConcatKdf<H> = crate::iso11770_6::Okdf3<H, i32>;

    /// Single Step Key Derivation Function, Option 1-hash based, NIST SP800-56C
    pub type SskdfHash<H> = crate::iso11770_6::Okdf3<H, u32>;

    /// Single Step Key Derivation Function, Option 2-hmac based, NIST SP800-56C
    pub type SskdfMac<H> = crate::iso11770_6::Okdf6<H, u32>;

    /// Two step key derivation, NIST SP800-56C
    pub type TwoStepKdfExtract<'a,M> = crate::iso11770_6::Ktf1<M>;

    /// Two step key derivation Expand Options are from SP 800-108
    pub type TwoStepKdfExpandCounterMode<M,I> = crate::nistsp800_108::NistKdfCtrStartMode<M,I>;
    pub type TwoStepKdfExpandFeedbackMode<M,I> = crate::nistsp800_108::NistKdfFeedbackModeWithCounter<M,I>;
    pub type TwoStepKdfExpandDblPipeline<M,C> = crate::nistsp800_108::NistKdfDblPipeline<M,C>;
}

/// Key derivation functions described in NIST SP 800-108 
pub mod nistsp800_108 {
    /// Specialization of Kpf2 as described by NIST in SP800-108 - Counter Mode
    /// Nist counter mode doesn't include the desired length at the end of the input
    pub type NistKdfCtrStartMode<M,I> = crate::iso11770_6::Kpf2<M,I,super::u0>; 
    pub type NistKdfFeedbackModeWithCounter<M,I> = crate::iso11770_6::Kpf3<M,I,super::u0>; // Nist KDF feedback mode doesnt include the Lb field in the data to be MAC'd
    pub type NistKdfFeedbackModeNoCounter<M> = crate::iso11770_6::Kpf3<M,super::u0,super::u0>; // Nist KDF feedback mode doesnt include the Lb field in the data to be MAC'd
    
    // Version of NIST SP800-108 with the following conditions
    //  Counter is after feedback variable (y)
    //  Counter can be u0, u8, u16, u32 or u64
    //  Length field is not present, unless manually added to the infos parameter 
    pub type NistKdfDblPipeline<M,C> = crate::iso11770_6::Kpf4<M,C,super::u0>;
}

/// Key derivation function as used in early versions of TLS, newer versions use HKDF
pub mod rfc5246_tls {
    pub type Tls1Prf<M> = crate::iso11770_6::Kpf4<M,super::u0,super::u0>;
}

/// Hash based, two stage KDF as described in RFC 5869
pub mod rfc5869_hkdf {
    pub type HkdfExtract<H> = crate::iso11770_6::Ktf1<H>;
    pub type HkdfExpand<H> = crate::iso11770_6::Kpf1<H, u8>;
    #[cfg(feature="rustcrypto-hmac")]
    pub type Hkdf<D> = crate::iso11770_6::Tkdf1<hmac::HmacReset<D>,u8>;
    pub type Hkdf2<M> = crate::iso11770_6::Tkdf1<M,u8>;
}

/// Key derivation functions described in the EMV specifications
pub mod emv {
    pub type EmvSessionKeyType = crate::misc::EmvSessionKeyType;
    pub type EmvCommonSessionKdf<E> = crate::misc::EmvCommonSessionKdf<E>;
    /// CMAC based KDF defined by EMV in Book E, will only output a key the same size as the block size
    #[cfg(feature="rustcrypto-cmac")]
    pub type EmvCmacKdf<A> = crate::iso11770_6::Ktf1<cmac::Cmac<A>>;
    #[cfg(all(feature="rustcrypto-cmac", feature="rustcrypto-aes"))]
    pub type EmvCmacAes128 = EmvCmacKdf<aes::Aes128>;
}

/// Key derivation function used by SSH as described in RFC 4253
pub mod rfc4253_ssh {
    pub type SshKdf<H> = crate::misc::SshKdf<H>;
}



///
/// Some of the KDFs are generic with respect to a counter. This struct implements a 
/// counter of zero size, ie it outputs an empty array when requested for to_be_bytes
/// This allows it to be used for KDFs which allow for a variable with length counter field,
/// and also allow the counter to be skipped
/// 
#[derive(Copy,Clone)]
#[allow(non_camel_case_types)]
pub struct u0 ();
impl AddAssign for u0{
    fn add_assign(&mut self, _other: Self) {
    }
}
impl Add for u0{
    type Output = Self;
    fn add (self, _other: Self) -> Self {
        return self
    }
}
impl ToBytes for u0{
    type Bytes=[u8;0];
    fn to_be_bytes(&self) -> Self::Bytes {
        []
    }
    fn to_le_bytes(&self) -> Self::Bytes {
        []
    }
}
impl One for u0 {
    fn one() -> Self {
        u0()
    }
}
impl Zero for u0 {
    fn zero() -> Self {
        u0()
    }
    fn is_zero(&self) -> bool {
        return false;
    }
}
impl Mul for u0 {
    fn mul(self, _: u0) -> <Self as Mul<u0>>::Output { u0() }
    type Output = u0;
}
impl From<u32> for u0 {
    fn from(_: u32) -> Self { u0() }
}
impl From<usize> for u0 {
    fn from(_: usize) -> Self { u0() }
}
impl From<u16> for u0 {
    fn from(_: u16) -> Self { u0() }
}
impl PartialEq for u0 {
    fn eq(&self, _other: &Self) -> bool {
        return false;
    }
}












// pub trait Kdf3 {
    
//     fn derive_self_secrets_others_into<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), ()>;

//     // functions with self
//     fn derive_self_secrets_others<'a,'b,L: ArrayLength<u8>> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> GenericArray<u8,L> where Self: Sized
//     { 
//         let mut out = GenericArray::default();
//         self.derive_self_secrets_others_into ( secrets, other_data, &mut out).unwrap();
//         return out;
//     }
//     fn derive_self_secret_others<'a, L: ArrayLength<u8>> ( &self, secret: &'a[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> GenericArray<u8,L> where Self: Sized { 
//         return self.derive_self_secrets_others(once(secret), other_data);
//     }
//     fn derive_self_secret_other<L: ArrayLength<u8>> ( &self, secret: &[u8], other_data: &[u8]) -> GenericArray<u8,L> where Self: Sized/*where Self: OutputSizeUser + Sized*/ {
//         return self.derive_self_secret_others(secret, [other_data])
//     }
//     fn derive_self_secrets_other<'a,L: ArrayLength<u8>> (&self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other: &[u8]) -> GenericArray<u8,L> where Self: Sized {
//         return self.derive_self_secrets_others(secrets, once(other));
//     }

//     // functions without self and without salt
//     fn derive_secrets_others<'a, 'c: 'a, L: ArrayLength<u8>> ( secrets: impl IntoIterator<Item=&'c[u8]> + Clone, other_data: impl IntoIterator<Item=&'c[u8]> + Clone) -> GenericArray<u8,L> where Self: Default {
//         return Self::default().derive_self_secrets_others(secrets, other_data);
//     }
//     fn derive_secret_others<'a, L:ArrayLength<u8>> ( secret: &'a[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> GenericArray<u8,L> where Self: Default { 
//         return Self::derive_secrets_others(once(secret), other_data);
//     }
//     fn derive_secret_other<'a, 'c:'a, L: ArrayLength<u8>> ( secret: &'a[u8], other: &[u8]) -> GenericArray<u8,L> where Self: Default /*OutputSizeUser + Default*/{
//         return Self::derive_secret_others(secret, once(other));
//     }
//     fn derive_secrets_other<'a, 'c:'a, L: ArrayLength<u8>> ( secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other: &'a[u8]) -> GenericArray<u8,L> where Self: Default /*OutputSizeUser + Default*/{
//         return Self::derive_secrets_others(secrets, once(other));
//     }

//     // functiosn without self, but with salt
//     fn derive_secrets_salt_others<'a,'b, L: ArrayLength<u8>> ( secrets: impl IntoIterator<Item=&'a[u8]> + Clone, salt: &[u8], other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> GenericArray<u8,L> 
//         where Self: Default + InitSalt
//     { 
//         return Self::derive_self_secrets_others(&Self::new_with_salt(salt), secrets, other_data);
//     }
//     fn derive_secret_salt_others<'a, L:ArrayLength<u8>> ( secret: &[u8], salt: &[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone) -> GenericArray<u8,L> where Self: Default + InitSalt { 
//         return Self::derive_secrets_salt_others(once(secret), salt, other_data);
//     }
//     fn derive_secret_salt_other<'a, L: ArrayLength<u8>> ( prk: &'a [u8], salt: &'a[u8], infos: &[u8]) -> GenericArray<u8, L> where Self: Default + InitSalt {
//        return Self::derive_secret_salt_others(prk, salt, once(infos));
//     }
//     fn derive_salt_secret<'a, 'c: 'a, L:ArrayLength<u8>>( salt: &'c[u8], secret: &'c[u8]) -> GenericArray<u8,L> where Self: Kdf + Default + InitSalt {
//         return <Self as Kdf3>::derive_secret_salt_others(secret, salt, None);
//     }
// }
