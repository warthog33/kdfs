
use std::marker::PhantomData;

#[cfg(feature="rustcrypto-salsa20")]
use aead::consts::*;
#[cfg(feature="rustcrypto-cshake")]
use cshake::{CShake128, CShake256};

#[cfg(feature="rustcrypto-salsa20")]
use crate::KdfFixed;

// #[cfg(feature="rustcrypto-salsa20")]
// use digest::Update;

use aead::{KeyInit};
use cipher::{BlockCipherEncrypt, BlockSizeUser, KeyIvInit, StreamCipher};
use digest::{Digest, FixedOutputReset, OutputSizeUser, ExtendableOutput, XofReader};
use hybrid_array::{Array, ArraySize};
use hybrid_array::typenum::Unsigned;
#[cfg(feature="rustcrypto-cshake")]
use shake::{Shake128, Shake256}; //, CShake128, CShake256 };

use crate::{iso11770_6::{block_loop, iter_to_generic_array, Okdf1}, InitSalt, Kdf};


use crate::{Error};

///
/// Kdf based upon a stream cipher as used by SRTP.
/// 
/// This test vector is from NIST, <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/srtp.zip>
/// ```
/// use hex_literal::hex;
/// use aes::Aes128;
/// use kdfs::misc::StreamCipherKdf;
/// use hybrid_array::sizes::U20;
/// use crate::kdfs::Kdf;
/// 
/// let k_master = hex!("c4809f6d369888728e26adb532129890");
/// let master_salt = hex!("0e23006c6c044f5662400e9d1bd6");
/// let _kdr = hex!("000000000000");
/// let _index = hex!("487165649cca");
/// let exp_k_e = hex!("dc382192ab65108a86b259b61b3af46f");
/// let exp_k_a = hex!("b83937fb321792ee87b788193be5a4e3bd326ee4");
///
/// let key_id = hex!("0000000000000001000000000000");
/// let calc_k_a = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_salt_other::<U20>(&k_master, &master_salt, &key_id).unwrap();
/// assert! ( calc_k_a == exp_k_a );
///```

pub struct StreamCipherKdf<S: StreamCipher + KeyIvInit> 
where <S as cipher::IvSizeUser>::IvSize: hybrid_array::ArraySize
{
    //salt: GenericArray<u8, S::IvSize>,
    salt: Array<u8, S::IvSize>,
}


impl <S: StreamCipher + KeyIvInit> Default for StreamCipherKdf<S> 
where <S as cipher::IvSizeUser>::IvSize: hybrid_array::ArraySize
{
    fn default() -> Self {
        //Self{salt: GenericArray::default()}
        Self{salt: Array::default()}
    }
}

impl <S: StreamCipher + KeyIvInit> InitSalt for StreamCipherKdf<S> 
where <S as cipher::IvSizeUser>::IvSize: hybrid_array::ArraySize
{
    fn new_with_salt ( salt: &[u8] ) -> Self {
        //let mut salt2 = GenericArray::default();
        let mut salt2 = Array::default();
        salt2[0..salt.len()].copy_from_slice(salt);
        Self{salt: salt2}
    }
}

impl <S: StreamCipher + KeyIvInit> Kdf for StreamCipherKdf<S> 
where <S as cipher::IvSizeUser>::IvSize: hybrid_array::ArraySize
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error> {

        let mut iv = iter_to_generic_array(other_data);

        (0..self.salt.len()).for_each(|i| iv[i] ^= self.salt[i]);

        let mut encryptor = S::new(&iter_to_generic_array(secret), &iv);
        encryptor.apply_keystream(out);
        Ok(())
    }
    
}


 

///
/// KDF used in SSH, doesn't quite match any of the ISO18033 algorithms because for multiple blocks it uses 
/// the hash of the entire previous set of blocks, rather than just the previous block as per the feedback mode
/// 
/// It is specified in RFC 4251 and in NIST SP 800-135.
/// 
/// 
/// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt xcghash:01234 -kdfopt session_id:4567 -kdfopt type:A -binary SSHKDF | xxd -p 
//   f3c2fb78cf931bd0fb84dd093baa27e5
///
/// ```
/// use hex_literal::hex;
/// use sha2::Sha256;
/// use kdfs::{rfc4253_ssh::SshKdf};
/// use hybrid_array::typenum::U32;
/// 
/// let key = hex!( "09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
/// let xcghash = b"01234";
/// let sessionid = b"4567";
/// let ssh_type = 'A' as u8; //b"A";
/// let exp_result = hex!( "f3c2fb78cf931bd0fb84dd093baa27e552b72b188d999d0cdfc8050726c39358");
/// 
/// let result = SshKdf::<Sha256>::derive::<U32> ( &key, xcghash, ssh_type, sessionid ).unwrap();
/// assert! ( result == exp_result);
/// ```
pub struct SshKdf<H: Digest> ( PhantomData<H>);

impl<H: Digest+FixedOutputReset> SshKdf<H> 
where <H as OutputSizeUser>::OutputSize: ArraySize
{
    //pub fn derive<L:ArrayLength<u8>> ( key: &[u8], xgd_hash: &[u8], key_type: u8, session_id: &[u8] ) -> GenericArray<u8, L>
    pub fn derive<L:ArraySize> ( key: &[u8], xgd_hash: &[u8], key_type: u8, session_id: &[u8] ) -> Result<Array<u8, L>, Error>
    {
        let mut result = Vec::<u8>::new();
        while result.len() < L::USIZE {
            let hash_output = if result.len() == 0 {
                Okdf1::<H>::derive_secret_others::<H::OutputSize>(key, [xgd_hash, &[key_type], session_id])
            } else {
                Okdf1::<H>::derive_secret_others::<H::OutputSize>(key, [xgd_hash, &result])
            };
            result.extend(hash_output?);
        }
        result.truncate(L::USIZE);
        //return GenericArray::<u8,L>::from_slice(&result).clone();
        //return Array::<u8,L>::from_slice(&result).clone();
        Array::<u8,L>::try_from(result.as_slice()).map_err(|_|Error::InvalidLength)
    }

}


///
/// Implementation of the KDF defined by EMV in Book 2, 4.4 A1.3.1. 
/// Also works with KDF from EMV in Book E, 7.2 providing the correct derivation data is provided.
/// It works by encrypting a block containing the derivation data with the provided symmetric key.
/// Where the output is two blocks, a 
/// 
/// The E parameter represents a block cipher
/// L is the length of the output, the KDF is designed for either 1x or 2x block length
pub struct EmvCommonSessionKdf<E: BlockSizeUser + KeyInit> {
    phantom: PhantomData<E>,
}


impl<E:BlockSizeUser + KeyInit> Default for EmvCommonSessionKdf<E> {
    fn default() -> Self {
        Self { phantom: Default::default()}
    }
}


impl<E:BlockSizeUser + BlockCipherEncrypt + KeyInit> Kdf for EmvCommonSessionKdf<E> {
    
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error>  {

        let encryptor = E::new(&iter_to_generic_array(secret));
        let derivation_data_block = iter_to_generic_array::<E::BlockSize> (other_data);
        let out_len = out.len();
        
        return block_loop(0, &[], out, |counter,_|{
            let mut block = derivation_data_block.clone();
            if out_len > E::BlockSize::USIZE { // Multiple blocks needed
                block[2] = match counter {
                    0 => 0xF0,
                    1 => 0x0F,
                    _ => panic! ( "unsupported output length")
                };
            }
            encryptor.encrypt_block(&mut block);
            block
        });
        
    }
}


///
/// Options for byte 1 of the derivation data as used to derive different session keys in EMV Book 3
/// 
pub enum EmvSessionKeyType {
    SessionKeyConfidentiality = 1,
    SessionKeyIntegrity = 2,
}

///
/// Single block encryption based KDF defined by EMV in Book E, 7.2
/// Output a key the same size as the block size
/// 
impl<B:BlockSizeUser + BlockCipherEncrypt+KeyInit> EmvCommonSessionKdf<B> 
where B::BlockSize: ArraySize
{
    //pub fn derive_session_key ( secret_key: &[u8], key_type: EmvSessionKeyType ) -> GenericArray<u8,B::BlockSize> {
    pub fn derive_session_key ( secret_key: &[u8], key_type: EmvSessionKeyType ) -> Result<Array<u8,B::BlockSize>, Error> {
        EmvCommonSessionKdf::<B>::derive_secret_other(secret_key, &[key_type as u8, 1,0,0x54,0x33,0x4A,0x32,0x59,0x57,0x77,0x3D,0xA5,0xA5, 0xA5, 0x1,0x80])
    }
}






///
/// Pseudo-kdf where the output is simply the concatenation of all the input fields
/// This is useful occaionally where a function requires a KDF to be input, but
/// no key derivation is needed.
///
#[derive(Clone)]
pub struct PassThroughKdf {}

impl Default for PassThroughKdf {
    fn default() -> Self {
        PassThroughKdf{}
    }
}

impl Kdf for PassThroughKdf {
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error>  {
        let mut out_vec = Vec::new();
        secret.into_iter().for_each (|v| out_vec.extend(v));
        other_data.into_iter().for_each (|v| out_vec.extend(v));
        out.copy_from_slice(&out_vec);
        //let mut out = out;
        // for v in secret.into_iter() {
        //     out[..v.len()].copy_from_slice(v);
        //     out = &mut out[v.len()..];
        // }
        //secret.into_iter().for_each (|v| {out[0..v.len()].copy_from_slice(v); out = &mut out[v.len()..]});

        Ok(())
    }
}



    

///
/// Implementation of the NaCl cryptobox algorithm
/// 
#[derive(Clone)]
pub struct CryptoBoxKdf<D: Digest> {
    phantom: PhantomData<D>,
}

impl<D: Digest> Default for CryptoBoxKdf<D> {
    fn default() -> CryptoBoxKdf<D> {
        return CryptoBoxKdf::<D>{ phantom: PhantomData};
    }
}

#[cfg(feature="rustcrypto-salsa20")]
impl<D: Digest> KdfFixed for CryptoBoxKdf<D> {
    type OutputSize = U56;
}


#[cfg(feature="rustcrypto-salsa20")]
impl<D: Digest> Kdf for CryptoBoxKdf<D> {
    fn derive_self_secrets_others_into<'c,'b> ( &self, secret: impl IntoIterator<Item=&'c[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), Error>
    {
        let input = Array::<u8, U16>::default();
        let secret2 = iter_to_generic_array::<U32>(secret);
        let h = salsa20::hsalsa::<U10> ( &secret2, &input); // Returns 256 bits

        let mut hasher = D::new();
        other_data.into_iter().for_each(|v| hasher.update(v));

        let hashed_other = hasher.finalize();
        
        out[0..32].copy_from_slice(h.as_slice());
        out[32..56].copy_from_slice(&hashed_other[0..24]);
        Ok(())
    }
}




/// Apply the KDF trait to any XOF function, works well with Shake128 and Shake256
impl<X: ExtendableOutput + Default> Kdf for X
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
        let mut hasher = X::default();
        secret.into_iter().for_each (|v|hasher.update(v));
        other_data.into_iter().for_each(|v|hasher.update(v));
        hasher.finalize_xof().read(out);
        Ok(())
    }
}


/// Wrapper for a customizable extendable output function which implements the KDF as defined in 
pub struct CShakeKdf<C>(PhantomData<C>);

impl<C> Default for CShakeKdf<C>
{
    fn default() -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature="rustcrypto-cshake")]
impl<C> Kdf for CShakeKdf<C>
where C: digest::CustomizedInit + ExtendableOutput
{
    fn derive_self_secrets_others_into<'a,'b>( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
        let customization: Vec<u8> = other_data.into_iter().flatten().map(|v|*v).collect();
        self.derive_self_secrets_other_into(secrets, &customization, out)
    }
    fn derive_self_secrets_other_into<'a>(&self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: &[u8], out: &mut [u8]) -> Result<(), crate::Error>
    {
        let mut hasher = C::new_customized(&other_data);
        secret.into_iter().for_each (|v|hasher.update(v));
        hasher.finalize_xof().read(out);
        return Ok(())
    }
}
// #[cfg(feature="rustcrypto-cshake")]
// impl<C> Update for CShakeKdf<C>
// where C: CustomizedInit + ExtendableOutput
// {
//     fn update(&mut self, data: &[u8]) {
//         todo!(); //C::update(self, data);
//     }
// }

// #[cfg(feature="rustcrypto-cshake")]
// impl<C> ExtendableOutput for CShakeKdf<C>
// where C: CustomizedInit + ExtendableOutput
// {
//     type Reader = C::Reader;

//     fn finalize_xof(self) -> Self::Reader {
//         todo!()
//         //C::finalize_xof(self)
//     }
// }


pub struct Kmac128Kdf<'a>(&'a[u8]);

impl<'a> Kmac128Kdf<'a>{
    pub fn new(value: &'a[u8]) -> Self {
        Self(value)
    }
}
impl<'a> Default for Kmac128Kdf<'a>
{
    fn default() -> Self {
        Self(&[])
    }
}
impl<'c> Kdf for Kmac128Kdf<'c>
{
    fn derive_self_secrets_others_into<'a,'b>(&self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
        let secret: Vec<&[u8]> = secrets.into_iter().collect();
        let mut hasher = tiny_keccak::Kmac::v128(&secret.concat(), self.0);
        other_data.into_iter().for_each (|v|tiny_keccak::Hasher::update(&mut hasher, v));
        tiny_keccak::Hasher::finalize(hasher, out);
        Ok(())
        // K = key, X = input
        //let newX = bytepad(encode_string(K), 168) || X || right_encode(L);
        // return cShake128(newX, L, “KMAC”, S)
        //hasher. 
    }
}

pub struct Kmac256Kdf<'a>(&'a[u8]);

impl<'a> Kmac256Kdf<'a>{
    pub fn new(value: &'a[u8]) -> Self {
        Self(value)
    }
}
impl<'a> Default for Kmac256Kdf<'a>
{
    fn default() -> Self {
        Self(&[])
    }
}
impl<'c> Kdf for Kmac256Kdf<'c>
{
    fn derive_self_secrets_others_into<'a,'b>(&self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
        let secret: Vec<&[u8]> = secrets.into_iter().collect();
        let mut hasher = tiny_keccak::Kmac::v256(&secret.concat(), self.0);
        other_data.into_iter().for_each (|v|tiny_keccak::Hasher::update(&mut hasher, v));
        tiny_keccak::Hasher::finalize(hasher, out);
        Ok(())
        // K = key, X = input
        //let newX = bytepad(encode_string(K), 168) || X || right_encode(L);
        // return cShake128(newX, L, “KMAC”, S)
        //hasher. 
    }
}



///
/// Xof structures are automatically extended to KDFs via a generic implementation
/// This type can be used as a KDF
/// 
#[cfg(feature="rustcrypto-cshake")]
pub type Shake128Kdf = Shake128;
///
/// Xof structures are automatically extended to KDFs via a generic implementation
/// This type can be used as a KDF
///  
#[cfg(feature="rustcrypto-cshake")]
pub type Shake256Kdf = Shake256;
///
/// CShake can be used as a base for a KDF, in this case using CShake128 with the other_data used as the customization
///  
#[cfg(feature="rustcrypto-cshake")]
//pub type CShake128Kdf = CShakeKdf<CShake128>;
pub type CShake128Kdf = CShakeKdf<CShake128>;
///
/// CShake can be used as a base for a KDF, in this case using CShake256 with the other_data used as the customization
///  
#[cfg(feature="rustcrypto-cshake")]
pub type CShake256Kdf = CShakeKdf<CShake256>;





// impl KdfLabelled for sha3::Shake128
// {
//     fn new_with_label ( label: &'static[u8]) -> Self {
//         todo!()
//     }

//     fn derive_self_secret_label_other<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: &'c[u8]) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }

//     fn derive_self_secret_label_others<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }
// }

// impl KdfLabelled for sha3::Shake256
// {
//     fn new_with_label ( label: &'static[u8]) -> Self {
//         todo!()
//     }

//     fn derive_self_secret_label_other<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: &'c[u8]) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }

//     fn derive_self_secret_label_others<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }
// }

// impl<const DS: u8> KdfLabelled for sha3::TurboShake128<DS>
// {
//     fn new_with_label ( label: &'static[u8]) -> Self {
//         todo!()
//     }

//     fn derive_self_secret_label_other<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: &'c[u8]) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }

//     fn derive_self_secret_label_others<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }
// }

// impl<const DS: u8> KdfLabelled for sha3::TurboShake256<DS>
// {
//     fn new_with_label ( label: &'static[u8]) -> Self {
//         todo!()
//     }

//     fn derive_self_secret_label_other<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: &'c[u8]) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }

//     fn derive_self_secret_label_others<'a, 'b, 'c, L:ArraySize> ( &self, secret: &'a[u8], label: &'b[u8], other: impl IntoIterator<Item=&'c[u8]> + Clone) -> Result<Array<u8,L>,Error> {
//         todo!()
//     }
// }
