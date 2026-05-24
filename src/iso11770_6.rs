use std::{marker::PhantomData, ops::AddAssign};

//use crypto_common::KeyInit;
//use crypto_common::generic_array::{GenericArray, ArrayLength};
use digest::{Digest, FixedOutputReset, OutputSizeUser, Mac, Update};
use cipher::{KeyInit};
use hybrid_array::{ArraySize, Array};
use num_traits::{One, ToBytes, Zero};
use hybrid_array::typenum::Unsigned;
//use generic_array::{GenericArray, ArrayLength};
use crate::{Error, GetExpand, GetExtract, KdfLabelled, Label};

use crate::{InitSalt, Kdf, KdfFixed, TwoStepKdf};

///
/// Utility function which splits the output buffer into chunks and calls the closure to get the contents
/// If the counter wraps then the routine returns an InvalidBufferSize error
/// 
pub fn block_loop<F,L,I> ( mut counter: I, salt: &[u8], out: &mut [u8], mut get_block: F ) -> Result<(), Error>
where   L: ArraySize,
        F: FnMut(I, &[u8]) -> Array<u8, L>,
        I: One + Zero + Copy + AddAssign<I>,
{
    let mut prev_block: &[u8] = salt;
    
    for chunk in out.chunks_mut(L::USIZE) {
        chunk.copy_from_slice(&get_block(counter, prev_block)[..chunk.len()]);
        prev_block = chunk;
        counter += I::one();
        if counter.is_zero() { return Err(Error::InvalidBufferSize) }
    }
    return Ok(())
}


///
/// Utility function which accepts an iterator of slices and concenates them
/// into a single GenericArray. Pads with zeros if the data is shorter than the expected length
/// 
pub fn iter_to_generic_array<'a, L> (iter: impl IntoIterator<Item=&'a[u8]>) -> Array<u8, L>
    where L: ArraySize,
{
    let mut iter2 = iter.into_iter().flatten();
    Array::from_fn(|_|{*iter2.next().unwrap_or(&0) } )

    // let mut result = Array::<u8, L>::default();
    // let mut res_iter = result.iter_mut();

    // //Copy all bytes from secret into the key ready for encryption
    // iter.into_iter().for_each(|v_arr| {
    //     v_arr.iter().for_each(|v|{ *res_iter.next().unwrap() = *v })
    // });
    

    //     match iter2.next() {
    //         Some(v) => *v,
    //         None => 0,
    //     }
    // });
    // //let result: Array::<u8, L> = iter.into_iter().flatten().map(|v|*v).collect();

    // return result2;
    // println! ( "L={}", L::USIZE);
    // iter.into_iter().flatten().map(|v|*v).collect()
}

pub fn iter_to_vec<'a> (iter: impl IntoIterator<Item=&'a[u8]>) -> Vec<u8>
{
    iter.into_iter().flatten().map(|v|*v).collect::<Vec<u8>>()
}

///
/// Simple hash kdf which concatenates the secret with optional derivation data (which could be called a salt)
/// and outputs the result. Output size is equal to the hash output size
/// ISO 11770-8, OKDF1. 
/// Equivalent to P1363 key derivation function
/// 
/// // From NIST SHA Test vectors, a the 512 bit input vector split into a secret and salt/other data field
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
/// use kdfs::{Kdf, iso11770_6};
/// use aead::consts::U32;
/// 
/// let secret = hex!("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8");
/// let salt = hex!("a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509");
/// let exp_derived_key = hex!("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa");
/// 
/// let result = iso11770_6::Okdf1::<sha2::Sha256>::derive_secret_other::<U32>(&secret, &salt).unwrap();
/// assert! ( result == exp_derived_key);
/// ```

#[derive(Clone)]
pub struct Okdf1<H: Digest> {
    hasher: PhantomData<H>,
}

impl<H:Digest> Default for Okdf1<H> 
{
    fn default () -> Okdf1<H> {
        return Self {hasher: PhantomData };
    }
}

///
/// Output size of Okdf1 is equal to the outputsize of the underlying digest function
/// 
impl<H:Digest+FixedOutputReset> KdfFixed for Okdf1<H>
where <H as digest::OutputSizeUser>::OutputSize: hybrid_array::ArraySize
{
    type OutputSize = <H as OutputSizeUser>::OutputSize;
}

///
/// Derive by passing all inputs to the digest function and returning the output
/// 
impl<H:Digest+Update> Kdf for Okdf1<H>
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> 
    {
        let mut hasher = H::new();
        secret.into_iter().for_each(|v| Digest::update(&mut hasher, v));
        other_data.into_iter().for_each(|v| Update::update(&mut hasher, v));
        
        if out.len() == H::OutputSize::USIZE { 
            Ok(out.copy_from_slice(&hasher.finalize()))
        } else {
            Err(Error::InvalidBufferSize) 
        }
    }
}





///
/// Implementation of OKDF2 from ISO 11770-8
/// Equivalent to ANSI X9.42 key derivation when used with a 32 bit counter and algorithm id is 
/// a DER ASN.1 encoded id
///
/// Mapping of value between ISO 11770-8 and this code is as follows
///  hash-function, h -> Generic parameter H which implements the Rust Crypto Digest trait
///  hash length, Lh -> Generic sub-parameter H::OutputSize 
///  counter, c -> Generic parameter C which implements AddAssign (+1) and ToBytes conversion. Only big-endian byte conversion is supported
///  algorithm id, a -> algorithm as specified during the struct new function
///  output size, Lk -> size of out parameter
///  key, k -> out parameter
///  salt, t -> salt 
///  secret, s -> secret
///  auxiliary secret, u -> other_data
///  
///  
/// Test vector is from X9.42:2003 D.5.2
/// ```
/// use hex_literal::hex;
/// use sha1::Sha1;
/// use kdfs::{Kdf, iso11770_6::Okdf2, ansi_x9_42::X942Asn1Kdf};
/// use cipher::consts::*;
/// 
/// let zz = hex!("5E10 B967 A956 0685 3E52 8F04 262A D18A 4767 C761 1639 7139 1E17 CB05 A216 68D4 CE2B 9F15 1617 4080 42CE 0919 5838 23FD 346D 1751 FBE2 341A F2EE 0461 B62F 100F FAD4 F723 F70C 18B3 8238 ED18 3E93 98C8 CA51 7EE0 CBBE FFF9 C594 71FE 2780 9392 4089 480D BC5A 38E9 A1A9 7D23 0381 0684 7D0D 22EC F85F 49A8 6182 1199 BAFC B0D7 4E6A CFFD 7D14 2765 EBF4 C712 414F E4B6 AB95 7F4C B466 B466 0128 9BB8 2060 4282 7284 2EE2 8F11 3CD1 1F39 431C BFFD 8232 54CE 472E 2105 E49B 3D7F 113B 8250 76E6 2645 8580 7BC4 6454 665F 27C5 E4E1 A4BD 0347 0486 3229 81FD C894 CCA1 E293 0987 C92C 15A3 8BC4 2EB3 8810 E867 C443 2F07 259E C00C DBBB 0FB9 9E17 27C7 06DA 58DD");
/// let algorithm_id = hex!("30 09 06 07 2A 86 48 CE 3F 01 02");
/// let supp_priv_info = hex!("4A6F 686E 204B 656E 6E65 6479 2061 6E64 2046 7269 656E 6473");
/// let exp_res = hex!("31B0 CA24 DF4A FDE9 B6D6 44E9 DC3B 030E 429D 7E15 2D90 9C8F BFCA 0A16 AA3E D5EA 2B56 5E12 DE3D FCDC");
/// 
/// let res = Okdf2::<Sha1,u32>::new(&algorithm_id, &[]).derive_self_secret_other::<U40>(&zz, &supp_priv_info).unwrap();
/// assert! ( res == exp_res);
/// 
/// let res2 = X942Asn1Kdf::<Sha1>::new(&algorithm_id, &[]).derive_self_secret_other::<U40>(&zz, &supp_priv_info).unwrap();
/// assert! ( res2 == exp_res);
/// ```
pub struct Okdf2<'a, H, C> 
where   H: Digest,
        C: Copy + AddAssign<C> + ToBytes + One,
{
    algorithm: &'a [u8],
    salt: &'a [u8],
    hasher: PhantomData<H>,
    init_counter: C,
}

impl<'a, H, C> Okdf2<'a, H, C> 
where   H: Digest + FixedOutputReset,
        C: Copy + AddAssign<C> + ToBytes + One
{
    pub fn new (algorithm: &'a [u8], salt: &'a [u8]) -> Okdf2<'a, H, C> {
        return Okdf2 { algorithm, salt, init_counter: C::one(), hasher: PhantomData};
    }
}

impl <'a, H, C> Kdf for Okdf2<'a, H, C> 
where   H:Digest + FixedOutputReset,
        C:  Copy + AddAssign<C> + ToBytes + One + PartialEq + Zero, 
{
    fn derive_self_secrets_others_into<'c,'b>( &self, secret: impl IntoIterator<Item=&'c[u8]>+Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut hasher = H::new();
        return block_loop ( self.init_counter.clone(), &[], out, |counter, _| {
            secret.clone().into_iter().for_each(|v| Digest::update ( &mut hasher, v ));
            Digest::update (&mut hasher, self.algorithm );
            Digest::update (&mut hasher, counter.to_be_bytes().as_ref());
            Digest::update ( &mut hasher, self.salt);
            other_data.clone().into_iter().for_each(|v| Digest::update ( &mut hasher, v));
            hasher.finalize_reset()
        });
    }
}



///
/// Simple hash kdf which concatenates a counter, the secret and with any supplied derivation data
/// and outputs the result. Outputsize is variable. If counter is omitted, then outputsize should be smaller than 
/// output of the hash function
/// ISO 11770-8, OKDF3
/// 
/// The mapping of variable in ISO 11770-3 OKDF3 to this code is as follows:
///  hash-function, h -> Generic Digest H
///  hash-output length, Lh -> H::OutputSize
///  counter, c -> Generic Integer C
///  counter length, Lc -> Output of C::to_be_bytes (only byte big endian encoding is supported)
///  secret, s -> secret: &[u8]
///  salt, t -> salt: &[u8]
///  auxiliary secret, u -> other_data (passed as parameter)
/// 
/// Apparently a superset of NIST SP/800-56A Concatenation key derivation function and
/// NIST  SP800 56A ASN.1 key derivation mechanism - ISO 11770-3 key derivation function)
/// Option 1 of single-step KDF in NIST SP 800-56A:2013 5.8.1.1
/// Option 1 of single-step KDF in NIST SP 800-56C:2020 4.1 Option 1)
///
/// Test vector created using openssl
/// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -binary SSKDF | xxd -p
///    75607159f86a412bd889ad4c3d52da77
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
/// use kdfs::{Kdf, iso11770_6::Okdf3, nistsp800_56::SskdfHash};
/// use cipher::typenum::consts::*;
/// 
/// let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
/// let info = hex!("123456");
/// let output_with_info = hex!("75607159f86a412bd889ad4c3d52da77");
///
/// let result = Okdf3::<Sha256,u32>::derive_secret_other::<U16> ( &sharedsecret, &info).unwrap();
/// assert! ( result == output_with_info);
/// 
/// let result2 = SskdfHash::<Sha256>::derive_secret_other::<U16> ( &sharedsecret, &info).unwrap();
/// assert! ( result2 == output_with_info);
/// ```
#[derive (Clone)]
pub struct Okdf3<H: Digest, I: Copy + AddAssign<I>> {
    hasher: PhantomData<H>,
    salt: Vec<u8>,
    phantom: PhantomData<I>,
}

///
/// This constructor accepts an other_info parameter which is appended to the auxiliary secret
/// as passed in the derive function. It allows for the setting of a part of the auxiliary secret
/// during setup
/// 
impl<H: Digest + FixedOutputReset, I> Default for Okdf3<H,I> 
    where I:  Copy + AddAssign<I> + ToBytes + One
{
    fn default() -> Self {
        Self::new_with_salt(&[])
        
    }
}

///
/// As per the ISO specification, the salt is added to the hash after the
/// secret, but before other info
/// 
impl<H: Digest + FixedOutputReset, I> InitSalt for Okdf3<H,I> 
    where I:  Copy + AddAssign<I> + ToBytes + One
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        Self { hasher: PhantomData, salt: salt.to_vec(), phantom: PhantomData, }
    }
}

impl<H: Digest + FixedOutputReset, I> Kdf for Okdf3<H,I> 
    where I:  Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut hasher = H::new();
        
        return block_loop ( I::one(), &[], out, |counter, _| {
            Digest::update(&mut hasher, counter.to_be_bytes().as_ref());
            secret.clone().into_iter().for_each(|v|Digest::update(&mut hasher, v));
            Digest::update(&mut hasher, &self.salt);
            other_data.clone().into_iter().for_each(|v|Digest::update(&mut hasher, v));
            //Digest::update(&mut self.hasher, &self.other_info);
            hasher.finalize_reset()
        });
    }
}





///
/// Hash KDF which allows for longer output than the hash function generates
/// ISO 11770-8, OKDF4
/// Apparently Okdf4 is a generalization of ANSI X9.63 KDF, if used with a 32 bit counter
///
/// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:012345 -binary X963KDF | xxd -p
///  53f87b89304e66181917ea7ba5a199d9
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
/// use kdfs::{Kdf, iso11770_6::Okdf4, ansi_x9_63::X963Kdf};
/// use cipher::typenum::consts::*;
/// 
/// let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
/// let info = hex!("012345");
/// let output_with_info = hex!("53f87b89304e66181917ea7ba5a199d9");
///
/// let result_with_info = Okdf4::<Sha256, u32>::derive_secret_other::<U16>(&sharedsecret, &info).unwrap();
/// assert! ( result_with_info == output_with_info); 
/// 
/// let result_with_info = X963Kdf::<Sha256>::derive_secret_other::<U16>(&sharedsecret, &info).unwrap();
/// assert! ( result_with_info == output_with_info); 
/// ```
#[derive(Clone)]
pub struct Okdf4<H: Digest, I: Copy > {
    hasher: PhantomData<H>,
    phantom: PhantomData<I>,
    salt: Vec<u8>,
}

impl <'a,H:Digest,I: Copy + One + AddAssign<I> + ToBytes> Default for Okdf4<H,I> {
    fn default () -> Self {
        return Self::new_with_salt(&[]);
    }
}

impl <'a,H:Digest,I: Copy + One + AddAssign<I> + ToBytes> InitSalt for Okdf4<H,I> {
    fn new_with_salt ( salt: &[u8] ) -> Self {
        Self { hasher: PhantomData, salt: salt.to_vec(), phantom: PhantomData, }
    }
}

impl <H:Digest + FixedOutputReset,I: Copy + One + AddAssign<I> + ToBytes + PartialEq + Zero> Kdf for Okdf4<H,I> 
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut hasher = H::new();

        return block_loop(I::one(), &[], out, |counter, _| {
            secret.clone().into_iter().for_each(|v|Digest::update(&mut hasher, v));
            Digest::update ( &mut hasher, counter.to_be_bytes().as_ref());
            other_data.clone().into_iter().for_each(|v|Digest::update ( &mut hasher, v ));
            Digest::update(&mut hasher, &self.salt);
            hasher.finalize_reset()
        });

    }

}
// impl <'c,H:Digest + FixedOutputReset,I: Copy + One + AddAssign<I> + ToBytes, L2:ArrayLength<u8>> Kdf for Okdf4<'c,H,I,L2> {
//     type OutputSize = L2;
//     #[cfg(not(feature = "iter_based"))]
//     fn derive_from_secrets_others ( secret: &[&[u8]], other_info: &[&[u8]] ) -> GenericArray<u8,L2>
//     {
//         println! ( "L2={:02X?}", L2::ISIZE);
//         return block_loop2(I::one(), &[], |counter, _| {
//             calc_hash::<H>(&[secret, &[counter.to_be_bytes().as_ref()], other_info])
//         });
//     }
//     #[cfg(feature = "iter_based")]
//     // // fn derive_iter<'a, 'c, 'e, I1, I2, I3 > ( secret: &I1, _salt: &I2, other_info: &I3) -> GenericArray<u8,Self::OutputSize>
//     // // where I1: IntoIterator<Item=&'a&'a[u8]> + Clone , 
//     // //       I2: IntoIterator<Item=&'c&'c[u8]> + Clone, 
//     // //       I3: IntoIterator<Item=&'e&'e[u8]> + Clone,
//     // fn derive_iter<'a> ( secret : impl IntoIterator<Item=&'a[u8]>,  _salt: impl IntoIterator<Item=&'a[u8]>, derivation_data: impl IntoIterator<Item=&'a[u8]>) -> GenericArray<u8, Self::OutputSize>
//     // {
//     //     return block_loop2(I::one(), &[], |counter, _| {
//     //         //calc_hash::<H>(secret_key, counter.to_be_bytes().as_ref(), other_info, &[], &[])
//     //         //calc_hash_iter::<H>(secret.clone(), once(&counter.to_be_bytes().as_ref()), other_info.clone())
//     //         Zeroizing::new(calc_hash_iter::<H>(once(counter.to_be_bytes().as_ref())))
//     //     });
//     // }
    
//     fn derive_secrets_others<'a,'b> ( secret : impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> GenericArray<u8,Self::OutputSize> {
//        //let secret: Vec<&[u8]> = secret.into_iter().collect();
//         //let other_info : Vec<&[u8]> = other_data.into_iter().collect();

//         let mut self2 = Self::new();
//         secret.into_iter().for_each(|v| self2.set_secret(v));
//         other_data.into_iter().for_each(|v|self2.update(v));
//         return self2.finalize_fixed()


//         // let mut hasher = H::new();
//         // return block_loop2(I::one(), &[], |counter, _| {
//         //     //calc_hash::<H>(&[&secret, &[counter.to_be_bytes().as_ref()], &other_info])
//         //     //let c = counter.to_be_bytes();
//         //     secret.clone().into_iter().for_each(|v|Digest::update (&mut hasher, v));
//         //     Digest::update ( &mut hasher, counter.to_be_bytes().as_ref());
//         //     other_data.clone().into_iter().for_each(|v|Digest::update ( &mut hasher, v));

//         //     hasher.finalize_reset()

//         //     //calc_hash_iter3::<H>(secret.clone(), [counter.to_be_bytes().as_ref()], other_data.clone()).into()
//         // });
//     }
// }

// impl<'c, H: Digest + FixedOutputReset, I: Copy + One + AddAssign<I> + ToBytes, L2: ArrayLength<u8>> KdfWithContext for Okdf4<'c,H,I,L2>
// {
//     type OutputSize = L2;
//     #[cfg(not(feature = "iter_based"))]
//     fn derive_from_self_secrets_others ( &self, secret_key:&[&[u8]], derivation_data: &[&[u8]]) -> GenericArray<u8,L2> {
//         return Self::derive_from_secrets_others(secret_key, derivation_data);
//     }

//     #[cfg(feature = "iter_based")]
//     //fn derive_from_self_secrets_others<'a,'b> ( &self, secret : impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> GenericArray<u8,Self::OutputSize>
//     fn derive_from_self_secrets_others<'a,'b, F, G> ( &'a self, secrets : F, other_data: G) -> GenericArray<u8,Self::OutputSize>
//     where   F: IntoIterator<Item=&'a[u8]> + Clone, <F as IntoIterator>::IntoIter: Clone,
//             G: IntoIterator<Item=&'a[u8]> + Clone, <G as IntoIterator>::IntoIter: Clone
//     {
//         return Self::derive_secrets_others(secrets, other_data);
//     }
   
// }


/**
 * OKDF5 as defined in ISO 11770-8
 * The two KDFs in ISO 18033-2 are specialization of OKDF5 with counter as a 32 bit big endian value
 * ??X9.63
 * These kdfs are based on a hash function. X9.63 allows for an additional 
 * SharedInfo field which is not present in the 18033-2 KDFs,
 * N defines the starting value for the counter, either 0(KDF1) or 1(KDF2)
 */
/// TestSamples vectors from ISO 18033-2, section C.2.1 and C.6.2
/// ```
/// use hex_literal::hex;
/// use sha1::Sha1;
/// use kdfs::{Kdf, iso11770_6::Okdf5, iso18033_2::{Kdf1, Kdf2 as OtherKdf2}};
/// use digest::consts::*;
/// 
/// let peh = hex!("4e9752632f973db43ed3d06ffd5bd9e741af0f855cbc556b73ab530affd7850c\
///                 a4c93d4b91d73b47db8718c05e296151e036cf9ba980cef6563af244438cac1b");
/// let z = hex!("5110f7e54f656e70c71ea2067c901570088a1eb1b230000abba1b2df4b774bed54\
///                 3c0325b7083f2b477d5c02ddcafdfec0725672da2cbed39baf75f02dc078d0");
/// let k = hex!("23e41472d780bfbb2daafd85a8fcdf8641fdca4d9f539a4ad175c473ca0f498728\
///             931bc311baa2c957ab528935aa22954075a2899ab1ce8ff5ba90a049aeba8cbb9019\
///             bccfc5c24c815ac8a1106e163936597b5d06ba4b52377ca48d82621b2768373a2103\
///             88998b964c11b0a2780c12c49cdea2cb454543fb3b725b026443d9");
/// 
/// let k_calc = Okdf5::<Sha1, 0>::derive_secret_other::<U128>(&peh, &z).unwrap();
/// assert! ( k_calc == k);
///
/// let k_calc2 = Kdf1::<Sha1>::derive_secret_other::<U128>(&peh, &z).unwrap();
/// assert! ( k_calc2 == k);
/// 
/// let r = hex!("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741\
///             52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
///
/// let k2 = hex!("0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840f\
///             f32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a\
///             25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3\
///             837eea4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807");
/// 
/// let k_calc3 = Okdf5::<Sha1, 1>::derive_secret_other::<U128>(&r, &[]).unwrap();
/// assert! ( k_calc3 == k2);
/// 
/// let k_calc4 = OtherKdf2::<Sha1>::derive_secret_other::<U128>(&r, &[]).unwrap();
/// assert! ( k_calc4 == k2);
/// ```
/// 
#[derive(Clone)]
pub struct Okdf5<H: Digest, const N: u32> {
    hasher: PhantomData<H>,
}


impl<H: Digest, const N: u32> Default for Okdf5<H,N> {
    fn default() -> Self {
        Self{ hasher: PhantomData}
    }
}

impl<H: Digest + FixedOutputReset, const N: u32> Kdf for Okdf5<H,N> {
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut hasher = H::new();
        
        return block_loop ( N, &[], out, |counter,_| {
            other_data.clone().into_iter().for_each(|v|Digest::update(&mut hasher, v));
            secret.clone().into_iter().for_each(|v|Digest::update(&mut hasher, v));
            //Digest::update(&mut hasher, counter.to_be_bytes().as_ref());
            Digest::update(&mut hasher, counter.to_be_bytes());
            //Digest::update(&mut hasher, <[u8; 4] as AsRef<T>>::as_ref(&counter.to_be_bytes()));
            hasher.finalize_reset()
        });
    }
}
 

//
// OWF6 as defined in ISO 11770-8. The parameters defined in ISO 1177-8 are mapped to function parameters as follows
//   MAC algorithm f -> Generic Parameter M which is a class implementing the Rust Crypto Mac trait and having an output length as M::OutputSize
//   Counter c with length Lc bits -> Generic Parameter I which is class implmenting an integer counter, e.g. u8, u16 or u32. The current implemntation assumes big endian\
//   Secret s -> Function Parameter secret which is a byte slice
//   Salt t' -> Function parameter salt, a byte slice
///  Salt t -> Element combined with the other_data parameter as they are processed together 
//   Auxiliary Secret u -> Function parameter other_data, an iterator over byte slices
//   Output Length Lb -> Size of out buffer into which the result will be written

//   
// NIST Option 2 of the single-step KDF mechanism specified in NIST/SP 800-56A (Revision 2):2013, 5.8.1.1,[9]
// is a special case of the OKDF6 mechanism,
//
/// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -kdfopt mac:HMAC -binary SSKDF | xxd -p 
///   989229c5a877a568660dad3cb07f4280
///
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use hmac::HmacReset;
/// use sha2::Sha256;
/// use kdfs::{ Kdf, iso11770_6::Okdf6, nistsp800_56::SskdfMac};
/// use digest::consts::*;
/// 
/// let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
/// let info = hex!("123456");
/// let output_with_info_hmac = hex!("989229c5a877a568660dad3cb07f4280");
/// 
/// let result = Okdf6::<HmacReset<Sha256>,u32>::derive_secret_other::<U16>(&sharedsecret, &info).unwrap();
/// assert! ( result == output_with_info_hmac);
/// 
/// let result2 = SskdfMac::<HmacReset<Sha256>>::derive_secret_other::<U16>(&sharedsecret, &info).unwrap();
/// assert! ( result2 == output_with_info_hmac);
/// ```


pub struct Okdf6<M: Mac, I> {
    hasher: M,
    phantom: PhantomData<I>,
}

impl<M, I> Default for Okdf6<M,I>
where M:Mac + KeyInit + FixedOutputReset,
    I: Copy + AddAssign<I> + ToBytes + One
{
    fn default() -> Self {
        //Self { hasher: M::new(&GenericArray::default()), phantom: PhantomData}
        Self { hasher: M::new(&Array::default()), phantom: PhantomData}
    }
}

impl<M, I> InitSalt for Okdf6<M,I>
where M:Mac + KeyInit + FixedOutputReset,
    I: Copy + AddAssign<I> + ToBytes + One
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        Self { hasher: M::new_from_slice(salt).unwrap(), phantom: PhantomData }
    }
}

impl<M, I> Kdf for Okdf6<M,I>
where M:Mac + KeyInit + FixedOutputReset + Clone,
    I: Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut hasher = self.hasher.clone();

        return block_loop(I::one(), &[], out, |counter, _| {
            Mac::update ( &mut hasher, counter.to_be_bytes().as_ref() );
            secret.clone().into_iter().for_each(|v|Mac::update(&mut hasher, v));
            other_data.clone().into_iter().for_each ( |v| Mac::update ( &mut hasher, v));
            hasher.finalize_reset().into_bytes()
        });
    }
}


///
/// KTF1 from ISO 11770-6
/// Key Extraction Function 1, which is similar to the key extraction part of HKDF
/// Applies a MAC function which uses the salt as the key, to the secret and any additional info.
/// Output is nominally the same size as the MAC output, which is slightly different to the definition
/// from ISO 11770-6 which allows for truncation
/// The CMAC KDF used in EMV for converting the ECDH shared secret into a key also uses this KDF
///
/// The terms used in the description of KTF1 from ISO 11770-6 are mapped into function parameters as follows
///   MAC function f -> Generic parameter M which implements rustcrypto trait Mac
///   Output Length Lk -> Length of out buffer, which is expected to equal the output size of the MAC function (M::OutputSize) - ISO 11770-8 allows for Lk smaller than MAC function output but this is not currently supported
///   Salt t -> Function parameter salt as a byte slice
///   Secret s -> Function parameter secret as a byte slice
///  The other_data parameter is used as to include additional data not strictly allowed by ISO 11770-8  
/// 
/// Sample from RFC 5869, Sample 1  
/// ```
/// use hex_literal::hex;
/// use hmac::HmacReset;
/// use sha2::Sha256;
/// use kdfs::{Kdf, InitSalt, iso11770_6::Ktf1, rfc5869_hkdf::HkdfExtract};
/// use digest::consts::*;
/// 
/// let ikm  = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");// (22 octets)
/// let salt = hex!("000102030405060708090a0b0c");// (13 octets)
/// let prk  = hex!("077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5");// (32 octets)
///
/// let prk_calc = Ktf1::<HmacReset<sha2::Sha256>>::derive_salt_secret::<U32>(&salt, &ikm).unwrap();
/// assert! ( prk_calc == prk);
/// 
/// let prk_calc2 = HkdfExtract::<HmacReset<sha2::Sha256>>::derive_salt_secret::<U32>(&salt, &ikm).unwrap();
/// assert! ( prk_calc2 == prk);
/// ```

#[derive(Clone)]
pub struct Ktf1<M: Mac> {
    maccer: M,
}

impl<M: Mac + KeyInit> Default for Ktf1<M> {
    fn default () -> Ktf1<M> {
        //return Ktf1 { maccer: M::new(&GenericArray::default())}
        return Ktf1 { maccer: M::new(&Array::default())}
    }
}
impl<M: Mac + KeyInit> InitSalt for Ktf1<M> {
    fn new_with_salt ( salt: &[u8] ) -> Self {
        return Ktf1 {  maccer: M::new_from_slice(salt).unwrap()}
    }
}
impl<'a,M: Mac + KeyInit + FixedOutputReset + Clone> KdfFixed for Ktf1<M> 
where <M as digest::OutputSizeUser>::OutputSize: hybrid_array::ArraySize
{
    type OutputSize = M::OutputSize;
}

impl<M: Mac + KeyInit + FixedOutputReset + Clone> Kdf for Ktf1<M> {
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut maccer = self.maccer.clone();
        
        secret.into_iter().for_each(|v|{Mac::update(&mut maccer, v); println!("secret={:02X?}", v)});
        other_data.into_iter().for_each(|v|{ Mac::update(&mut maccer, v); println!("other={:02X?}", v)});

        if out.len() <= M::OutputSize::USIZE { 
            // let mut buf = Array::default();
            // maccer.finalize_into_reset(&mut buf);
            // out.copy_from_slice(&buf);
            let result = maccer.finalize_reset();
            println! ( "result={:02X?}", result.as_bytes());
            Ok(out.copy_from_slice(&result.as_bytes()[0..out.len()]))
        // } else if out.len() < M::OutputSize::USIZE {
        //     let mut buf = Array::default();
        //     maccer.finalize_into_reset(&mut buf);
        //     out.copy_from_slice(&buf[0..out.len()]);
        } else {
            Err(Error::InvalidBufferSize)
        }
        
        //Ok(())
    }
}




///
/// KPF1 from ISO 11770-8
/// Same as the expand KDF as specified by NIST
///
/// km = Mac secret key (secret)
/// f = Mac function (M)
/// c = counter of an integer type (I) with length Lb
/// output lenght, Lb = length of output (out.len())
/// output, b = output string (out)
/// salt, t = other_data
/// 
/// c) Set y = empty bit string.
/// d) Set z = y.
/// e) For c = 1 to d:
///   1) Set y = fkm(y || t || c).
///   2) Set z = z || y.
/// f) Set b = the leftmost Lb bits of z.
/// 
/// Test vectors from RFC 5869
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use hmac::HmacReset;
/// use sha1::Sha1;
/// use kdfs::{Kdf, iso11770_6::Kpf1, rfc5869_hkdf::HkdfExpand};
/// use digest::consts::*;
/// 
/// let prk = hex!( "8adae09a2a307059478d309b26c4115a224cfaf6" );// (20 octets)
/// let okm = hex!( "0bd770a74d1160f7c9f12cd5912a06eb"
///                 "ff6adcae899d92191fe4305673ba2ffe"
///                 "8fa3f1a4e5ad79f3f334b3b202b2173c"
///                 "486ea37ce3d397ed034c7f9dfeb15c5e"
///                 "927336d0441f4c4300e2cff0d0900b52"
///                 "d3b4");
/// let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
///                 "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
///                 "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
///                 "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
///                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
/// let okm_calc = Kpf1::<HmacReset<Sha1>,u8>::derive_secret_other::<U82>(&prk, &info).unwrap();
/// assert! ( okm == okm_calc);
/// 
/// let okm_calc2 = HkdfExpand::<HmacReset<Sha1>>::derive_secret_other::<U82>(&prk, &info).unwrap();
/// assert! ( okm == okm_calc2);
/// ```
#[derive(Clone)]
pub struct Kpf1<M: Mac, I: Copy> {
    phantom: PhantomData<M>,
    phantom2: PhantomData<I>,
    salt: Vec<u8>,
}

impl<'b, M, I> Default for Kpf1<M, I>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One,
{
    fn default() -> Self {
        Self { phantom: PhantomData, phantom2: PhantomData, salt: Vec::new()}
    }
}
impl<'b, M, I> InitSalt for Kpf1<M, I>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One,
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        Self { phantom: PhantomData, phantom2: PhantomData, salt: salt.to_vec()}
    }
}

impl<'c, M, I> Kdf for Kpf1<M, I>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero,
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        self.derive_self_secret_others_into( &iter_to_vec(secret), other_data, out)
        
        // let mut maccer = M::new(&iter_to_generic_array(secret));

        // return block_loop ( I::one(), &[], out, |counter, prev_mac| {
        //     Mac::update (&mut maccer, prev_mac);
        //     Mac::update ( &mut maccer, &self.salt );
        //     other_data.clone().into_iter().for_each ( |v| Mac::update ( &mut maccer, v));
        //     Mac::update ( &mut maccer, counter.to_be_bytes().as_ref() );
        //     maccer.finalize_reset().into_bytes()
        // });
    }
    fn derive_self_secret_others_into<'a>( &self, secret: &[u8], other_data: impl IntoIterator<Item=&'a[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let mut maccer = M::new_from_slice(secret)?;
        println !( "kpf1 secret={:02X?}", secret);

        return block_loop ( I::one(), &[], out, |counter, prev_mac| {
            Mac::update (&mut maccer, prev_mac);
            Mac::update ( &mut maccer, &self.salt );
            println! ( "kpf1 salt={:02X?}", self.salt);
            other_data.clone().into_iter().for_each ( |v| { Mac::update ( &mut maccer, v); println!( "kpf1 other={:02X?}", v)});
            Mac::update ( &mut maccer, counter.to_be_bytes().as_ref() );
            maccer.finalize_reset().into_bytes()
        });
    }

    
}



///
/// Kpf2 from ISO 11770-6
/// Similar to KDF in Counter Mode from NIST SP 800-108:2009. Only the counter at the start variant is supported
/// by this implementation.
///
/// c) Set z = empty bit string.
/// d) For c = 1 to d:
///      1) Set z = z || fkm(c || p || t || Lb)
/// e) return leftmost Lb bits of z
///
/// There are 4 generic parameters
/// M - MAC Function to use, must implement Mac trait
/// I - Counter type, typically an unsigned integer type, must implement Copy + AddAssign\<I\> + ToBytes + One traits
/// O - Output Length type used as Lb, e.g. u8, u16 etc. Must implement Copy + From\<u16\> + ToBytes traits
/// L - Length of output key, e.g. U16
/// 
/// Example from NIST test vectors SP 108 Counter Mode. The NIST counter mode KDF doesn't include the
/// output length in the key derivation calculation, therefore the type u0 is used for generic parameter 3
/// [PRF=CMAC_AES128]
/// [CTRLOCATION=BEFORE_FIXED]
/// [RLEN=8_BITS]
/// L = 128
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use cmac::Cmac;
/// use kdfs::{ Kdf, iso11770_6::Kpf2, nistsp800_108::NistKdfCtrStartMode, u0};
/// use digest::consts::*;
/// 
/// let ki = hex!("dff1e50ac0b69dc40f1051d46c2b069c");
/// let fixed_input_data = hex!("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
/// let ko = hex!("8be8f0869b3c0ba97b71863d1b9f7813");
/// 
/// let result = Kpf2::<Cmac<Aes128>,u8,u0>::derive_secret_other::<U16>(&ki, &fixed_input_data).unwrap();
/// assert! ( result == ko);
/// 
/// let result2 = NistKdfCtrStartMode::<Cmac<Aes128>,u8>::derive_secret_other::<U16>(&ki, &fixed_input_data).unwrap();
/// assert! ( result2== ko);
/// ```
/// 
pub struct Kpf2<M: Mac, I: Copy, O> {
    phantom: PhantomData<M>,
    phantom2: PhantomData<I>,
    phantom3: PhantomData<O>,
}

impl<M, I, O> Default for Kpf2<M, I, O>
where M:Mac + KeyInit,
    I:  Copy + AddAssign<I> + ToBytes + One,
    O:  Copy + From<u16> + ToBytes
{
    fn default() -> Self 
    { Self{phantom: PhantomData, phantom2: PhantomData, phantom3: PhantomData}}
}

impl<M, I, O> Kdf for Kpf2<M, I, O>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero,
    O:  Copy + From<u16> + ToBytes
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        self.derive_self_secret_others_into (&iter_to_vec(secret), other_data, out)
        //let lb = O::from(out.len() as u16 * 8).to_be_bytes();
        //let mut macfunc = <M as KeyInit>::new(&iter_to_generic_array(secret));
            
        // return block_loop ( I::one(), &[], out, |counter, _| {
        //     Mac::update(&mut macfunc, counter.to_be_bytes().as_ref());
        //     other_data.clone().into_iter().for_each(|v|Mac::update(&mut macfunc, &v));
        //     Mac::update(&mut macfunc, lb.as_ref());
        //     macfunc.finalize_reset().into_bytes()
        // });
    }
    fn derive_self_secret_others_into<'b>( &self, secret: &[u8], other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let lb = O::from(out.len() as u16 * 8).to_be_bytes();
        let mut macfunc = <M as KeyInit>::new_from_slice(secret)?;
            
        return block_loop ( I::one(), &[], out, |counter, _| {
            Mac::update(&mut macfunc, counter.to_be_bytes().as_ref());
            other_data.clone().into_iter().for_each(|v|Mac::update(&mut macfunc, &v));
            Mac::update(&mut macfunc, lb.as_ref());
            macfunc.finalize_reset().into_bytes()
        });
    }
}


///
/// Kpf3 from ISO 11770-6
/// Similar to KDF in feedback mode from NIST/SP 800-108:2009 - IV/t' not currently supported
/// 
/// Mapping of parameters from ISO 11770-6 is as follows
///  MAC algorithm, f -> Generic parameter M implementing rust crypto trait Mac
///  MAC length, Lf -> Generic sub-parameter, M::OutputSize
///  Max counter, Mc -> ??
///  Counter, c -> Generic parameter type I, which implements +1 and to_bytes. u0 can be used as a zero length type which effectively excludes the counter from the calculations 
///  Output length, Lb -> Parameter out, length
///  Output buffer, b -> Parameter out as a mutable byte slice
///  Label p -> Function parameter other_data (first part, if any)
///  Salt1, t -> Function parameter other_data (last part, if any)
///  Salt2, t' -> Parameter salt
///  Secret MAC key, km -> Parameter secret
/// c) Set y = t′.
/// d) Set z = empty string.
/// e) For c = 1 to d:
///    1) Set y = fkm(y || \[c\] || p || t || Lb).
///    2) Set z = z || y
///f) Set b = the leftmost Lb bits of z
///
/// M is the type of MAC to use
/// I is the type of counter, typically u8, u32 or u0 (do not use counter)
///
/// Example from NIST test vectors SP 108 Feedback Mode. The NIST feedback mode KDF doesn't include the
/// output length in the key derivation calculation, therefore the type u0 is used for generic parameter 3
/// [PRF=CMAC_AES128]
/// [CTRLOCATION=AFTER_ITER]
/// [RLEN=16_BITS]
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use cmac::Cmac;
/// use kdfs::{ Kdf, u0, iso11770_6::Kpf3, nistsp800_108::NistKdfFeedbackModeWithCounter};
/// use digest::consts::*;
/// 
/// let ki = hex!("d7f5fa7551645de0b36aecd46565f954");;
/// let fixed_input_data = hex!("fb5294ed40a0e4aa70a7be13913070a4c5cfc05f89b9f7dd26a493b8c63889c7c3b0b60dd6d598ffa296a426224c727a501946");
/// let ko = hex!("7164471f559812581a53aaf7fb6d6c53a1293115cda873887efcc7ce6b3a026b2d19f0d38db8590e218a2676df88f53cab3313ed63bd1e4828f3c066ea5eb1fd");
///
/// let result = Kpf3::<Cmac<Aes128>,u16,u0>::derive_secret_other::<U64>(&ki, &fixed_input_data).unwrap();
/// assert! ( result == ko);
/// 
/// let result2 = NistKdfFeedbackModeWithCounter::<Cmac<Aes128>,u16>::derive_secret_other::<U64>(&ki, &fixed_input_data ).unwrap();
/// assert! ( result2 == ko);
/// ```
/// 
pub struct Kpf3<M: Mac, I: Copy, O> {
    salt: Vec<u8>,
    counter: I,
    phantom: PhantomData<M>,
    phantom3: PhantomData<O>,

}

impl<M, I, O> Default for Kpf3<M, I, O>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One,
    O:  Copy + From<u16> + ToBytes
{
    fn default() -> Self {
        return Self::new_with_salt(&[]);
    }
}
impl<M, I, O> InitSalt for Kpf3<M, I, O>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One,
    O:  Copy + From<u16> + ToBytes
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        return Self{salt: salt.to_vec(), counter: I::one(), phantom: PhantomData, phantom3: PhantomData, }
    }
}

impl<M, I, O> Kdf for Kpf3<M, I, O>
where M:Mac + KeyInit + FixedOutputReset,
    I:  Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero,
    O:  Copy + From<u16> + ToBytes
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        self.derive_self_secret_others_into( &iter_to_vec(secret), other_data, out)
        // let lb = O::from(out.len() as u16 * 8 );
        // let mut macfunct = M::new(&iter_to_generic_array(secret));

        // return block_loop ( self.counter, &self.salt, out,|counter, prev| {
        //     Mac::update( &mut macfunct, prev);
        //     Mac::update( &mut macfunct, counter.to_be_bytes().as_ref());
        //     other_data.clone().into_iter().for_each(|v| Mac::update( &mut macfunct, v));
        //     Mac::update( &mut macfunct, lb.to_be_bytes().as_ref());
        //     Mac::finalize_reset(&mut macfunct).into_bytes()
        // });
    }
    fn derive_self_secret_others_into<'b>( &self, secret: &[u8], other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        
        let lb = O::from(out.len() as u16 * 8 );
        let mut macfunct = M::new_from_slice(secret)?;

        return block_loop ( self.counter, &self.salt, out,|counter, prev| {
            Mac::update( &mut macfunct, prev);
            Mac::update( &mut macfunct, counter.to_be_bytes().as_ref());
            other_data.clone().into_iter().for_each(|v| Mac::update( &mut macfunct, v));
            Mac::update( &mut macfunct, lb.to_be_bytes().as_ref());
            Mac::finalize_reset(&mut macfunct).into_bytes()
        });
    }
}


///
/// Kpf4 from ISO 11770-6
/// Similar to KDF in double pipeline mode mode from NIST/SP 800-108:2009 5.3, where 'messages' includes c and Lb
/// Basis for TLS1 PRF, as defined in RF 5246
///
/// c) Set y = p || t || Lb.
/// d) Set z = empty string.
/// e) For c = 1 to d:
///   1) Set y =fkm(y).
///   2) Set z = z || fkm(y || \[c\] || p || t || Lb).
/// f) Set b = the leftmost Lb bits of z
///
/// I is the counter type, designed to be either u0, u8, u32, etc where u0 means not present
/// I is the length field, designed to be either u0, u8, u32, etc where u0 means not present
/// 
/// [PRF=CMAC_AES128]
/// [CTRLOCATION=AFTER_ITER]
/// [RLEN=8_BITS]
/// L = 512
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use cmac::Cmac;
/// use kdfs::{ Kdf, u0, iso11770_6::Kpf4, nistsp800_108::NistKdfDblPipeline };
/// use digest::consts::*;
///
/// let ki = hex!("08a5a251b8e4826fbf73292f4cd6c790");
/// let fixed_input_data = hex!("aa5acbce73a98d4c4f361d5c22a2cc6f6bdc30027aa31af1ba8b15a5bd5b6a34d133519ad1a82483c2d2a6dd9a97273a780421");
/// let ko = hex!("ff1c72ec38b8968a1ce0942a571a1f522ddd2a1c6ffc2b60c90bb54a5c0e9de40d289686cbff127b408ec64ef615b18c1abc0736ae4c94e33e54d832e686276e");
///
/// let result = Kpf4::<Cmac<Aes128>,u8,u0>::derive_secret_other::<U64>(&ki, &fixed_input_data).unwrap();
/// assert! ( result == ko);
/// 
/// let result2 = NistKdfDblPipeline::<Cmac<Aes128>,u8>::derive_secret_other::<U64>(&ki, &fixed_input_data).unwrap();
/// assert! ( result2 == ko);
/// ```

pub struct Kpf4<M: Mac, I: Copy, B> {
    counter: I,
    phantom: PhantomData<M>,
    phantom3: PhantomData<B>,
}

impl<M, I, B> Default for Kpf4<M, I, B>
where M:Mac + KeyInit + FixedOutputReset, 
    I:  Copy + AddAssign<I> + ToBytes + One,
    B: From<u32> + ToBytes,
{
    fn default() -> Self {
        Self { counter: I::one(), phantom: PhantomData, phantom3: PhantomData}
    }
}


impl<M, I, B> Kdf for Kpf4<M, I, B>
where M:Mac + KeyInit + FixedOutputReset, 
    I:  Copy + AddAssign<I> + ToBytes + One + PartialEq + Zero,
    B: From<usize> + ToBytes,
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        self.derive_self_secret_others_into(&iter_to_vec(secret), other_data, out)
        // let lb = B::from (out.len() * 8).to_be_bytes();
        // let mut hasher = <M as KeyInit>::new(&iter_to_generic_array(secret));

        // other_data.clone().into_iter().for_each(|v|Mac::update ( &mut hasher, v));
        // let mut y = hasher.finalize_reset().into_bytes();
        
        // return block_loop(self.counter, &[], out, |counter, _prev| {
        //     Mac::update ( &mut hasher, &y );
        //     Mac::update ( &mut hasher, counter.to_be_bytes().as_ref());
        //     other_data.clone().into_iter().for_each ( |v| Mac::update ( &mut hasher, v));
        //     Mac::update ( &mut hasher, lb.as_ref());
        //     let hash_output = hasher.finalize_reset().into_bytes();

        //     Mac::update(&mut hasher, &y);
        //     y = hasher.finalize_reset().into_bytes();

        //     hash_output
        // });
    }
    fn derive_self_secret_others_into<'b>( &self, secret: &[u8], other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let lb = B::from (out.len() * 8).to_be_bytes();
        let mut hasher = <M as KeyInit>::new_from_slice(secret)?;

        other_data.clone().into_iter().for_each(|v|Mac::update ( &mut hasher, v));
        let mut y = hasher.finalize_reset().into_bytes();
        
        return block_loop(self.counter, &[], out, |counter, _prev| {
            Mac::update ( &mut hasher, &y );
            Mac::update ( &mut hasher, counter.to_be_bytes().as_ref());
            other_data.clone().into_iter().for_each ( |v| Mac::update ( &mut hasher, v));
            Mac::update ( &mut hasher, lb.as_ref());
            let hash_output = hasher.finalize_reset().into_bytes();

            Mac::update(&mut hasher, &y);
            y = hasher.finalize_reset().into_bytes();

            hash_output
        });
    }
}


#[derive(Clone)]
pub struct Tkdf <KX: InitSalt + KdfFixed, KP: Kdf + Default>
{
    phantom: std::marker::PhantomData<KX>,
    phantom2: std::marker::PhantomData<KP>,
    extract: KX,
    expand: KP,
    //expand_others: Vec<u8>
}
impl <KX, KP > TwoStepKdf for Tkdf<KX, KP>
where KX: InitSalt + KdfFixed + Default,
    KP: Kdf + Default,
{
    type Extract = KX;
    type Expand = KP;
}

impl <'a, KX, KP > Default for Tkdf<KX, KP>
where KX: InitSalt + KdfFixed + Default,
    KP: Kdf +  Default,
{
    fn default () -> Self {
        return Self{phantom: PhantomData, phantom2: PhantomData, extract: KX::default(), expand: KP::default()}
    }
}

impl <KX, KP > InitSalt for Tkdf<KX, KP>
where KX: KdfFixed + Default + InitSalt,
    KP: Kdf +  Default,
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        return Self{phantom: PhantomData, phantom2: PhantomData, extract: KX::new_with_salt(salt), expand: KP::default()}
    }
}
impl <KX, KP > Tkdf<KX, KP>
where KX: KdfFixed + Default + InitSalt,
    KP: Kdf +  Default + InitSalt,
{
    pub fn new_with_add_info ( salt: &[u8] ) -> Self {
        return Self{phantom: PhantomData, phantom2: PhantomData, extract: KX::default(), expand: KP::new_with_salt(salt)}
    }
}

impl <KX, KP > Kdf for Tkdf<KX, KP>
where KX: InitSalt + KdfFixed + Default, //KdfWithSalt,
    KP: Kdf + Default,
    <KX as KdfFixed>::OutputSize: ArraySize
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {
        let km = self.extract.derive_self_secrets_others::<KX::OutputSize>(secrets, None)?;

        return self.expand.derive_self_secret_others_into ( &km, other_data, out);
    }
}

impl <KX: InitSalt + KdfFixed, KP: Default + Kdf> GetExtract for Tkdf<KX, KP>
{
    type T = KX;
    fn get_extract(&self) -> &Self::T {
        &self.extract
    }
}
impl <KX: InitSalt + KdfFixed, KP: Default + Kdf> GetExpand for Tkdf<KX, KP>
{
    type T = KP;
    fn get_expand(&self) -> &Self::T {
        &self.expand
    }
}

impl<KX,KP> KdfLabelled for Tkdf<KX, KP>
where KX: KdfLabelled + InitSalt + KdfFixed + Default,
    KP: KdfLabelled + Default,
    <KX as KdfFixed>::OutputSize: ArraySize
{
    fn new_with_label<L: Label>() -> Self {
        Self{expand: KP::new_with_label::<L>(), extract: KX::new_with_label::<L>(), phantom: PhantomData, phantom2: PhantomData}
    }    
    fn derive_self_secrets_label_others_into<'a, 'b, 'c> ( &self, _secrets: impl IntoIterator<Item=&'a[u8]> + Clone, _label: &'b[u8], _others: impl IntoIterator<Item=&'c[u8]> + Clone, _out: &mut[u8]) -> Result<(),Error> {
        todo!()// let km = self.extract.derive_self_secrets_label_others::<KX::OutputSize>(secrets, &[], others)?;
        // self.expand.derive_self_secrets_label_others_into ( once(km.as_slice()), &[], None, out)
    }
    
}


///
/// Implementation of TKDF1 from ISO 11770-6
/// Combined KTF1 extraction with TPF1 expansion
///
/// Similar to HKDF
///
///
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
/// use hmac::HmacReset;
/// use kdfs::{TwoStepKdf, Kdf, InitSalt, iso11770_6::Tkdf1, rfc5869_hkdf::Hkdf2};
/// use digest::consts::*;
/// 
/// let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
/// let salt = hex!("6789");
/// let partyu_info = hex!("123456");
/// let output_with_info_and_salt = hex!("410f65514d76b1ade8619a8c33a2b4d8");
/// 
/// let result = Tkdf1::<HmacReset<Sha256>,u8>::derive_secret_salt_other::<U16>(&sharedsecret, &salt,  &partyu_info).unwrap();
/// assert! ( result == output_with_info_and_salt);
/// 
/// let result2 = Hkdf2::<HmacReset<Sha256>>::derive_secret_salt_other::<U16>(&sharedsecret, &salt,  &partyu_info).unwrap();
/// assert! ( result2 == output_with_info_and_salt);
/// 
/// ```
/// 
pub type Tkdf1<M, I> = Tkdf<Ktf1::<M>, Kpf1::<M,I>>;



///
/// Implementation of TKDF2 from ISO 11770-6
/// Combined KTF1 extraction with TPF2 expansion
///
pub type Tkdf2<M,I> = Tkdf<Ktf1::<M>, Kpf2::<M,I,u32>>;














