

// #[cfg(feature = "cshake")]
// pub struct CShake256Kdf {}

// #[cfg(feature = "cshake")]
// impl Default for CShake256Kdf
// {
//     fn default() -> Self {
//         Self{}
//     }
// }

// impl Kdf for CShake256Kdf 
// //impl Kdf for CShake256 
// {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
//         let mut customization = Vec::new();
//         other_data.into_iter().for_each(|v|customization.extend(v));
//         let mut hasher = CShake256::new_customized(&customization);
//         secret.into_iter().for_each(|v|hasher.update(v));
//         hasher.finalize_xof().read(out);
//         return Ok(())
//     }
// }



// pub struct XofKdf<X: ExtendableOutput>( PhantomData<X> );

// impl<X: ExtendableOutput> Default for XofKdf <X>
// {
//     fn default() -> Self {
//         Self(PhantomData)
//     }
// }

// impl<X: ExtendableOutput + Default> Kdf for XofKdf <X>
// {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
        
//         //let mut hasher = CShake128::from_core(CShake128Core::new(&customization));
//         let mut hasher = X::default();
//         secret.into_iter().for_each (|v|{hasher.update(v); println!("i={v:02?}")});
//         other_data.into_iter().for_each(|v|hasher.update(v));
//         hasher.finalize_xof().read(out);
//         return Ok(())
//     }
// }


// impl<X: ExtendableOutput> TwoStepKdf for XofKdf<X>
// {
//     type Expand = Shake128KdfExpand;
//     type Extract = Shake128KdfExtract;
// }

// #[derive(Default)]
// pub struct Shake128KdfExpand;
// impl Kdf for Shake128KdfExpand {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
//         let mut hasher = Shake256::default();
//         secret.into_iter().for_each (|v|{hasher.update(v); println!( "input={:02X?}", v)});
//         other_data.into_iter().for_each(|v|{hasher.update(v); println!( "input={:02X?}", v)});
//         hasher.finalize_xof().read(out);
//         println! ( "Shake128KdfExpand = {:02X?}", out);
//         return Ok(())
//     }
// }

// #[derive(Default)]
// pub struct Shake128KdfExtract (Vec<u8>);
// impl InitSalt for Shake128KdfExtract {
//     fn new_with_salt ( salt: &[u8] ) -> Self {
//         Self(salt.to_vec())
//     } 
// }
// impl KdfFixed for Shake128KdfExtract {
//     type OutputSize = typenum::U32;
// }
// impl Kdf for Shake128KdfExtract {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]>, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), crate::Error> {
//         let mut hasher = Shake128::default();
//         secret.into_iter().for_each (|v|hasher.update(v));
//         hasher.update(&self.0);
//         other_data.into_iter().for_each(|v|hasher.update(v));
//         hasher.finalize_xof().read(out);
//         println! ( "Shake128KdfExtract = {:02X?}", out);
//         return Ok(())
//     }
// }