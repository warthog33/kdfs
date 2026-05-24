
use aes::{Aes128, Aes192, Aes256};
use cmac::Cmac;
use des::TdesEde2;
use digest::consts::*;
use hex_literal::hex;
use hmac::HmacReset;
use hybrid_array::Array;
use kdfs::Kdf;
use kdfs::iso11770_6::*;
use kdfs::misc::Kmac128Kdf;
use kdfs::misc::Kmac256Kdf;
use kdfs::rfc5869_hkdf::Hkdf;
use kdfs::misc::StreamCipherKdf;
use kdfs::*;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512, Sha224};

#[test]
// HKDF as specified in RFC 5869
fn test_case_1_5869 () {
    
    //let Hash = SHA-256
    let ikm  = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");// (22 octets)
    let salt = hex!("000102030405060708090a0b0c");// (13 octets)
    let info = hex!("f0f1f2f3f4f5f6f7f8f9"); // (10 octets)
    let _l    = 42;

    let prk  = hex!("077709362c2e32df0ddc3f0dc47bba63 90b6c73bb50f9c3122ec844ad7c2b3e5");// (32 octets)
    let okm  = hex! ( "3cb25f25faacd57a90434f64d0362f2a 2d2d0a90cf1a5a4c5db02d56ecc4c5bf 34007208d5b887185865");// (42 octets)

    //let prk_calc = HmacKdf::<sha2::Sha256>::extract (&salt, &ikm);
    //let prk_calc = MacKdfExtract::<Hmac<sha2::Sha256>>::derive(&salt, &ikm);
    //let prk_calc = MacKdfExtract::<Hmac<sha2::Sha256>>::derive_with_salt2(&ikm, &salt, &[]);

    //let h = HmacReset::<sha2::Sha256>::new(&Array::default());
    //h.finalize_into_reset();
    let prk_calc = kdfs::rfc5869_hkdf::HkdfExtract::<HmacReset<sha2::Sha256>>::derive_salt_secret::<U32>(&salt, &ikm).unwrap();

    assert! ( prk_calc == Array::from(prk));

    //let okm_calc = HmacKdf::<sha2::Sha256>::expand::<U42>(&prk, &info);
    //let okm_calc = rfc5869_hkdf::HkdfExpand::<Hmac<sha2::Sha256>>::derive_secret_other_variable::<U42>(&prk, &info);
    let okm_calc = kdfs::rfc5869_hkdf::HkdfExpand::<HmacReset<sha2::Sha256>>::derive_secret_other::<U42>(&prk, &info).unwrap();
    //assert! ( okm_calc.to_vec() == okm );
    assert! ( okm_calc == Array::from(okm) );
}

#[test]

// HKDF as specified in RFC 5869
fn test_case_2_5869 () {

    //Test with SHA-256 and longer inputs/outputs

    //Hash = SHA-256
    let ikm  = hex!("000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f"); // (80 octets)
   let salt = hex!("606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" );// (80 octets)
   let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" );// (80 octets)
   let _l    = 82;

   let prk  = hex!("06a6b88c5853361a06104c9ceb35b45c
          ef760014904671014a193f40c15fc244"); //(32 octets)
   let okm  = hex!("b11e398dc80327a1c8e7f78c596a4934
          4f012eda2d4efad8a050cc4c19afa97c
          59045a99cac7827271cb41c65e590e09
          da3275600c2f09b8367793a9aca3db71
          cc30c58179ec3e87c14c01d5c1f3434f
          1d87");// (82 octets)
    
    //let prk_calc = HmacKdf::<sha2::Sha256>::extract (&salt, &ikm);
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<sha2::Sha256>>::derive_salt_secret::<U32>(&salt, &ikm).unwrap();
    //let prk_calc = MacKdfExtract::<Hmac<sha2::Sha256>>::derive_with_salt2(&ikm, &salt, &[]);
    
    assert! ( prk_calc == prk);

    //let okm_calc = HmacKdf::<sha2::Sha256>::expand::<U82>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha2::Sha256>/* ,U82*/>::derive_secret_other::<U82>(&prk, &info).unwrap();
    assert! ( okm_calc == okm );
}

#[test]
fn test_case_3_5869()
{
   //Test with SHA-256 and zero-length salt/info

    //Hash = SHA-256
    let ikm  = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");// (22 octets)
    let salt = [0u8;0]; //(0 octets)
    let info  = [0u8;0]; //(0 octets)
    let _l    = 42;

    let prk  = hex!( "19ef24a32c717b167f33a91d6f648bdf 96596776afdb6377ac434c1c293ccb04" ); // (32 octets)
    let okm  = hex! ( "8da4e775a563c18f715f802a063c5a31 b8a11f5c5ee1879ec3454e5f3c738d2d 9d201395faa4b61a96c8" );// (42 octets)

    //let prk_calc = HmacKdf::<sha2::Sha256>::extract (&salt, &ikm);
    //let prk_calc = MacKdfExtract::<Hmac<sha2::Sha256>>::derive(&salt, &ikm);
    //let prk_calc = MacKdfExtract::<Hmac<sha2::Sha256>>::derive_with_salt2(&ikm, &salt, &[]) ;
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<sha2::Sha256>>::derive_salt_secret::<U32>(&salt, &ikm).unwrap();
    
    assert! ( prk_calc == prk);

    //let (prk_calc2, _) = hkdf::Hkdf::<_, hmac::Hmac<sha2::Sha256>>::extract(None, &ikm);
    //assert! ( prk_calc2.to_vec() == prk );
    
    //let okm_calc = HmacKdf::<sha2::Sha256>::expand::<U42>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha2::Sha256>>::derive_secret_other::<U42>(&prk, &info).unwrap();
    assert! ( okm_calc == okm );
}

#[test]
fn test_case_4_5869()
{
    // Test Case 4
    // Basic test case with SHA-1
    // Hash = SHA-1
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b");// (11 octets)
    let salt = hex! ( "000102030405060708090a0b0c");// (13 octets)
    let info = hex!( "f0f1f2f3f4f5f6f7f8f9"); // (10 octets)
    let _l    = 42;

    let prk  = hex!( "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243" );// (20 octets)
    let okm  = hex! ( "085a01ea1b10f36933068b56efa5ad81
       a4f14b822f5b091568a9cdd4f155fda2
       c22e422478d305f3f896" );// (42 octets)

    //let prk_calc = HmacKdf::<sha1::Sha1>::extract (&salt, &ikm);
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha1>>::derive_salt_secret::<U20>(&salt, &ikm).unwrap();
    //let prk_calc = HkdfSha1Extract::derive_with_salt2(&ikm, &salt, &[]);
    
    assert! ( prk_calc == prk);

    //let okm_calc = HmacKdf::<sha1::Sha1>::expand::<U42>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha1::Sha1>>::derive_secret_other::<U42>(&prk, &info).unwrap();
    assert! ( okm_calc == okm );
}


#[test]
fn test_case_5_ ()
{
    // A.5.  Test Case 5
    // Test with SHA-1 and longer inputs/outputs
    // Hash = SHA-1
    let ikm = hex!( "000102030405060708090a0b0c0d0e0f
       101112131415161718191a1b1c1d1e1f
       202122232425262728292a2b2c2d2e2f
       303132333435363738393a3b3c3d3e3f
       404142434445464748494a4b4c4d4e4f");// (80 octets)
    let salt = hex!("606162636465666768696a6b6c6d6e6f
       707172737475767778797a7b7c7d7e7f
       808182838485868788898a8b8c8d8e8f
       909192939495969798999a9b9c9d9e9f
       a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");// (80 octets)
    let info = hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
       c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
       d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
       e0e1e2e3e4e5e6e7e8e9eaebecedeeef
       f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");// (80 octets)
    let _l    = 82;

    let prk  = hex!( "8adae09a2a307059478d309b26c4115a224cfaf6" );// (20 octets)
    let okm = hex!("0bd770a74d1160f7c9f12cd5912a06eb
       ff6adcae899d92191fe4305673ba2ffe
       8fa3f1a4e5ad79f3f334b3b202b2173c
       486ea37ce3d397ed034c7f9dfeb15c5e
       927336d0441f4c4300e2cff0d0900b52
       d3b4");// (82 octets)

    //let prk_calc = HmacKdf::<sha1::Sha1>::extract (&salt, &ikm);
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha1>>::derive_salt_secret::<U20>(&salt, &ikm).unwrap();
    //let prk_calc = HkdfSha1Extract::derive_with_salt2(&ikm, &salt, &[]);
    
    assert! ( prk_calc == prk);

    //let okm_calc = HmacKdf::<sha1::Sha1>::expand::<U82>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha1::Sha1>>::derive_secret_other::<U82>(&prk, &info).unwrap();
    assert! ( okm_calc == okm);
}

#[test]
fn test_case_6_5869()
{
    //A.6.  Test Case 6
    //Test with SHA-1 and zero-length salt/info

    //Hash = SHA-1
    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");// (22 octets)
    let salt = [0u8;0]; //(0 octets)
    let info = [0u8;0]; //(0 octets)
    let _l    = 42;

    let prk  = hex!( "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01");// (20 octets)
    let okm  = hex!("0ac1af7002b3d761d1e55298da9d0506
       b9ae52057220a306e07b6b87e8df21d0
       ea00033de03984d34918");// (42 octets)

    //let prk_calc = HmacKdf::<sha1::Sha1>::extract (&salt, &ikm);
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha1>>::derive_salt_secret::<U20>(&salt, &ikm).unwrap();
    //let prk_calc = HkdfSha1Extract::derive_with_salt2(&ikm, &salt, &[]);
    assert! ( prk_calc == prk);

    //let okm_calc = HmacKdf::<sha1::Sha1>::expand::<U42>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha1::Sha1>>::derive_secret_other::<U42>(&prk, &info).unwrap();
    assert! ( okm_calc == Array::from(okm) );
}
#[test]
fn test_case_7_5869()
{
    //A.7.  Test Case 7
    //Test with SHA-1, salt not provided (defaults to HashLen zero octets),
    //zero-length info
    //Hash = SHA-1
    let ikm = hex!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");// (22 octets)
    let _salt: Option<&[u8]> = None; //not provided (defaults to HashLen zero octets)
    let info = [0u8; 0]; //(0 octets)
    let _l    = 42;

    let prk = hex!("2adccada18779e7c2077ad2eb19d3f3e731385dd");// (20 octets)
    let okm = hex!("2c91117204d745f3500d636a62f64f0a
       b3bae548aa53d423b0d1f27ebba6f5e5
       673a081d70cce7acfc48" );// (42 octets)
    
    //let prk_calc = HmacKdf::<sha1::Sha1>::extract (&[0u8;0]/*Salt is auto-padded by hmac */, &ikm);
    //let prk_calc = HkdfSha1Extract::derive(&[0u8;0], &ikm);
    let prk_calc = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha1>>::derive_salt_secret::<U20>(&[0u8;0], &ikm).unwrap();
    assert! ( prk_calc == prk);

    //let okm_calc = HmacKdf::<sha1::Sha1>::expand::<U42>(&prk, &info);
    let okm_calc = rfc5869_hkdf::HkdfExpand::<HmacReset<sha1::Sha1>>::derive_secret_other::<U42>(&prk, &info).unwrap();
    assert! ( okm_calc == okm );
}


#[test]
fn test_emv_key_derivation() {
    let master_key = hex!("0123456789abcdef123456789abcdef0");
    let derived_key_aes = hex!("2b06daf9580cb74d02319bc92cbd26a9");
    let derived_key_tdes = hex!("b19dd738a79e90c66cfe8aa6215c8d33");
    let atc = hex!("beef");
    
    let derived_key_aes2 = emv::EmvCommonSessionKdf::<Aes128>::derive_secret_other::<U16>(&master_key, &atc).unwrap();
    assert! ( derived_key_aes2 == derived_key_aes);

    let derived_key_tdes2 = emv::EmvCommonSessionKdf::<des::TdesEde2>::derive_secret_other::<U16>(&master_key, &atc).unwrap();
    assert! ( derived_key_tdes2 == derived_key_tdes);

}



#[test]
fn test_okdf1 () {
    let secret = [0xA5u8; 16];
    let salt = [0xBEu8; 16];
    let derived_key = [0xEBu8,0xB0,0x66,0xC7,0x05,0x8F,0x1F,0xE4,0xD2,0x72,0xE2,0xE5,0x32,0x36,0x32,0x2A,0x53,0x0C,0x0D,0x23,0x81,0x72,0x74,0xC2,0x8F,0x94,0x26,0xF4,0x76,0x10,0x1C,0xAC];
    
    let result = Okdf1::<sha2::Sha256>::derive_secret_other::<U32>(&secret, &salt).unwrap();
    assert! ( result == derived_key);

    // From NIST SHA Test vectors
    let secret2 = hex!("fe1f0fb02c9011f4c8c5905934ed15136771737ce31c5859e67f235fe594f5f6");
    let exp_derived_key = hex!("bbeaacc632c2a3db2a9b47f157ab54aa27776c6e74cf0bcaa91b06d5");

    let result2 = Okdf1::<sha2::Sha224>::derive_secret_other::<U28>(&secret2, &[]).unwrap();
    assert! ( result2 == exp_derived_key);

    // From NIST SHA Test vectors
    let secret3 = hex!("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8");
    let salt3 = hex!("a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509");
    let exp_derived_key3 = hex!("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa");

    let result3 = Okdf1::<sha2::Sha256>::derive_secret_other::<U32>(&secret3, &salt3).unwrap();
    assert! ( result3 == exp_derived_key3);
}

#[test]
fn test_okdf6 () {
    let secret = [0xA5u8; 16];
    let salt = [0xBEu8; 16];
    let auxiliary_secret = [12u8; 2];
    let derived_key = hex!("42585a0e7ac98f9408ca1f3f802f6ebd92d697664b846072fbc641599ccbb8e7");
    
    //let result = Okdf6::<Hmac<sha2::Sha256>,u32>::derive_from_secret_salt_other2_variable(&secret, &salt, &auxiliary_secret);
    let result = Okdf6::<HmacReset<sha2::Sha256>,u32>::new_with_salt(&salt).derive_self_secret_other::<U32>(&secret, &auxiliary_secret).unwrap();

    //println! ( "{result:02x}");
    assert! ( result == derived_key)
}


// Copied from test vectors 
#[test]
fn test_nist_sp800_108_countermode () {
    let ki = hex!("dff1e50ac0b69dc40f1051d46c2b069c");
    //FixedInputDataByteLen = 60
    let fixed_input_data = hex!("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5");
    let ko = hex!("8be8f0869b3c0ba97b71863d1b9f7813");

    let result = Kpf2::<Cmac<Aes128>, u8,u0>::derive_secret_other::<U16>(&ki, fixed_input_data.as_ref()).unwrap();
    //println! ( "cal={result:02x?}\nexp={ko:02x?}");
    assert! ( result == Array::from(ko));


    // [PRF=CMAC_AES192]
    // [CTRLOCATION=BEFORE_FIXED]
    // [RLEN=16_BITS]
    // COUNT=0
    // L = 128
    let ki = hex!("d7e8eefc503a39e70d931f16645958ad06fb789f0cbc518b");
    //FixedInputDataByteLen = 60
    let fixed_input_data = hex!("b10ea2d67904a8b3b7ce5eef7d9ee49768e8deb3506ee74a2ad8dd8661146fde74137a8f6dfc69a370945d15335e0d6403fa029da19d34140c7e3da0");
    let ko = hex!("95278b8883852f6676c587507b0aa162");

    let result = Kpf2::<Cmac<Aes192>,u16,u0>::derive_secret_other::<U16>(&ki, &fixed_input_data).unwrap();

    //println! ( "cal={result:02x?}\nexp={ko:02x?}");
    assert! ( result == ko);



    // [PRF=HMAC_SHA224]
    // [CTRLOCATION=BEFORE_FIXED]
    // [RLEN=32_BITS]
    
    // COUNT=0
    // L = 128
    let ki = hex!("f5cb7cc6207f5920dd60155ddb68c3fbbdf5104365305d2c1abcd311");
    //FixedInputDataByteLen = 60
    let fixed_input_data = hex!("4e5ac7539803da89581ee088c7d10235a10536360054b72b8e9f18f77c25af01019b290656b60428024ce01fccf49022d831941407e6bd27ff9e2d28");
    let ko = hex!("0adbaab43edd532b560a322c84ac540e");

    let result = Kpf2::<HmacReset<Sha224>,u32,u0>::derive_secret_other::<U16>(&ki, &fixed_input_data).unwrap();

    //println! ( "cal={result:02x?}\nexp={ko:02x?}");
    assert! ( result == ko);


    let ki: [u8; 16] = hex!("c3ba16a8ec864c0f6f27cea220eccaaa");
    //FixedInputDataByteLen = 60
    let fixed_input_data = hex!("c20ff015ea1e1c97fed4e973b46a9b2626cb3ac9a8776cb08d73d4534d3837ccf88e93d1682c6e779ea9f2f9ede47a2e07ef281d8867722b310c1cae");
    let ko = hex!("ceeaab29648cff00b89f7330076298b1e036d73ed7c5e61f2e97bd5ce0920f0f45133eaca3d3712b");

    let result = Kpf2::<Cmac<Aes128>,u8,u0>::derive_secret_other::<U40>(&ki, &fixed_input_data ).unwrap();

    //println! ( "cal={result:02x?}\nexp={ko:02x?}");
    assert! ( result == ko);

}

#[test]
fn test_nist_sp800_108_feedback_mode() {
    //[PRF=CMAC_AES128]
    //[CTRLOCATION=AFTER_ITER]
    //[RLEN=16_BITS]
    let ki = hex!("d7f5fa7551645de0b36aecd46565f954");
    //IVlen = 0
    //IV = 
    //FixedInputDataByteLen = 51
    let fixed_input_data = hex!("fb5294ed40a0e4aa70a7be13913070a4c5cfc05f89b9f7dd26a493b8c63889c7c3b0b60dd6d598ffa296a426224c727a501946");
    let ko = hex!("7164471f559812581a53aaf7fb6d6c53a1293115cda873887efcc7ce6b3a026b2d19f0d38db8590e218a2676df88f53cab3313ed63bd1e4828f3c066ea5eb1fd");

    let result = nistsp800_108::NistKdfFeedbackModeWithCounter::<Cmac<Aes128>,u16>::derive_secret_other::<U64>(&ki, &fixed_input_data ).unwrap();

    //println! ( "cal={result:02x?}\nexp={ko:02x?}");
    assert! ( result == ko);

    // [PRF=CMAC_AES128]
    // COUNT=0
    // L = 512
    let ki = hex!("5c996c922f65de97d4408373229814c6");
    //IVlen = 128
    let iv = hex!("28dc945cb8337ab5336c3e9b5bad21c7");
    //FixedInputDataByteLen = 51
    let fixed_input_data = hex!("62afe5fed91e797221a854336b0aadd8a05ad0e3c8345729897b2efcec5a1178a2fa4c063007b67a7015e0d6b7271ea8d86b44");
    let ko = hex!("88a9aae193abdd3fe8143bab66014ae41dc2d12ea9d08f5871588fc5d827924eb9942989d7a36d4b3b107997566472cad5942bd13cb5cff32b9dae30f1bb6300");

    let result = nistsp800_108::NistKdfFeedbackModeNoCounter::<Cmac<Aes128>>::derive_secret_salt_other::<U64>(&ki, &iv, &fixed_input_data).unwrap();
    assert! ( result == ko);


    // PRF=CMAC_TDES2]
    // COUNT=0
    // L = 512
    let ki = hex!("1cc91ac93ce93215c74ca11cb900fcb3");
    // IVlen = 64
    let iv = hex!("9e24eef3fe79719f");
    // FixedInputDataByteLen = 51
    let fixed_input_data = hex!("28400c621bc2f7ae04de8ab279009803885e7966b2391e7a2cf28ca458f83f48882135066d31f701fb46937cf867dabbfa1bac");
    let ko = hex!("3f46494db77b4497075e0abea59b15c4d97b5055e48eaf1db3c8601205bace9a6053c20867f6756ad0e2fc5c81c69f0427ef66ceb1d1d18f4f2678e10cb93913");

    let result = nistsp800_108::NistKdfFeedbackModeNoCounter::<Cmac<TdesEde2>>::derive_secret_salt_other::<U64>(&ki, &iv, &fixed_input_data).unwrap();
    assert! ( result == ko);

    let ki = hex!("91cce7832e1caf170f6961b6b65805c4cb487f719819a2343149040cf9d88d09d112db117c97dea0e15d7c0fa03727082c0909f420a10b9b082958ecb9ad3d21"); 
    let fixed_input_data = hex!("1a20ea91b6104c8d36b0353d7a2880c1e167b572857b78204e9206cb6ea06cace3555e87442debbc780f94f223c22a5819568a");
    let ko = hex!("819fe4adc7d6e06ec9700e4ba19291b9b2dd7c76b6ee85f3eec5f2bc5928311596a4a316875555a0ec467636122b3629d2f5ca092dbf620423c5650fc1a18a8b2cb1ffc8a1845751a5329a0d1a2a22119a1e129bb5c86d4c92cd6a189513ea8ea615b64e94fddfe2c79b3c50884454c7153103aba3af59cbb3ab35719e3291bb296bdce9d0a7d3f8a1c08cf68e5b74f556f3a389d89b5a55142b023bb0bde0899d3ed55f710a1bc0bc934aa736280fcdc90408417129fb0c57413b955ea8d919d59b3566a00edf54ff9d825c24d18f2fc6622ae0273982394953e45912f0967d6a398c446d8d9af7dd4048683ffd3415c318efe2a7f21a975cda34f84940c7c4995a");
    let result = nistsp800_108::NistKdfFeedbackModeNoCounter::<HmacReset<Sha512>>::derive_secret_other::<U258>(&ki, &fixed_input_data ).unwrap();

    assert! ( result == ko);
}



#[test]
fn test_nist_sp800_108_double_pipeline_mode() {
    // [PRF=CMAC_AES128]
    // [CTRLOCATION=AFTER_ITER]
    // [RLEN=8_BITS]

    // COUNT=0
    //L = 512
    let ki = hex!("08a5a251b8e4826fbf73292f4cd6c790");
    //FixedInputDataByteLen = 51
    let fixed_input_data = hex!("aa5acbce73a98d4c4f361d5c22a2cc6f6bdc30027aa31af1ba8b15a5bd5b6a34d133519ad1a82483c2d2a6dd9a97273a780421");
    let ko = hex!("ff1c72ec38b8968a1ce0942a571a1f522ddd2a1c6ffc2b60c90bb54a5c0e9de40d289686cbff127b408ec64ef615b18c1abc0736ae4c94e33e54d832e686276e");

    let result = nistsp800_108::NistKdfDblPipeline::<Cmac<Aes128>,u8>::derive_secret_other::<U64>(&ki, &fixed_input_data ).unwrap();

    //println! ( "exp={:02X?}\ncal={:02X?}",ko, result);
    assert! ( result == ko);

    let ki = hex!("2451975a33ab0c7535e00abe7b57982335b0471ad857a093c6765e6c58443852");
    let fixed_input_data = hex!("fb95eb3c47dcad3b783b045b29bcb6f5aefc0389735843b92b4d8fab97d61350b76b2a83442d7c5aa497aa1cf441760281a08b");
    let ko = hex!("2f157687f782c8b64325826e3c755194c70abffd9d78c4678924b9d73dcced86dcaf7dfa3bf56cf03fa45c7fca05ca1092c41bbd934131e95db2b204241a9d02");

    let result = nistsp800_108::NistKdfDblPipeline::<Cmac<Aes256>,u32>::derive_secret_other::<U64>(&ki, &fixed_input_data ).unwrap();

    //println! ( "exp={:02X?}\ncal={:02X?}",ko, result);
    assert! ( result == ko);


    //[PRF=CMAC_AES128]
    //COUNT=0
    //  L = 512
    let ki = hex!("ada2452f1f141a82c7a1b7d3e09ffed1");
    //FixedInputDataByteLen = 51
    let fixed_input_data = hex!("335660eb265d2044efa06eacd848d3f9f57d219011343318f3a964df4a6fb1bf6cbdee711c7fcbe73b8f257f992e47e8b065af");
    let ko = hex!("a73bd29176e38e761222ae07d639181f4b2c555a3b261815cde5d88a67c8b95c58b6b66ea4f10608c6d799b051519fc8e89de00cdc556350a7d966475086f9af");

    let result = nistsp800_108::NistKdfDblPipeline::<Cmac<Aes128>,u0>::derive_secret_other::<U64>(&ki, &fixed_input_data ).unwrap();

    //println! ( "exp={:02X?}\ncal={:02X?}",ko, result);
    assert! ( result == ko);

}

//
// Couple of test from openssl
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -binary X963KDF | xxd -p 
//  bbc69c6f314526506989ce92e238095d 
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:012345 -binary X963KDF | xxd -p
//  53f87b89304e66181917ea7ba5a199d9
#[test]
#[cfg(feature="rustcrypto-sha2")]
fn test_x963_kdf () {
    let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let info = hex!("012345");
    let output_no_info = hex!("bbc69c6f314526506989ce92e238095d");
    let output_with_info = hex!("53f87b89304e66181917ea7ba5a199d9");

    let result_no_info = ansi_x9_63::X963KdfSha256::derive_secret_other::<U16>(&sharedsecret, &[]).unwrap();
    assert! ( result_no_info == output_no_info);

    let result_with_info = ansi_x9_63::X963KdfSha256::derive_secret_other::<U16>(&sharedsecret, &info).unwrap();
    assert! ( result_with_info == output_with_info);

    // From NIST Test Vectors - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ansx963_2001.zip
    let z = hex!("fd17198b89ab39c4ab5d7cca363b82f9fd7e23c3984dc8a2");
    let shared_info = hex!("856a53f3e36a26bbc5792879f307cce2");
    let exp_res = hex!("6e5fad865cb4a51c95209b16df0cc490bc2c9064405c5bccd4ee4832a531fbe7f10cb79e2eab6ab1149fbd5a23cfdabc41242269c9df22f628c4424333855b64e95e2d4fb8469c669f17176c07d103376b10b384ec5763d8b8c610409f19aca8eb31f9d85cc61a8d6d4a03d03e5a506b78d6847e93d295ee548c65afedd2efec");

    let result2 = ansi_x9_63::X963KdfSha1::derive_secret_other::<U128>(&z, &shared_info).unwrap();
    //println! ( "result={result2:02X?}")
    assert! ( result2 == exp_res);
}


//
// Couple of test from openssl
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -binary -kdfopt cekalg:aes-128-wrap X942kdf-asn1 | xxd -p 
//   45a682e60ab52b1ae3edd2a1da7ec3f3
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -binary -kdfopt partyu-info:1234 -kdfopt cekalg:aes-128-wrap X942kdf-asn1 | xxd -p 
//   a04e55a7809594a06bf0910ba40e3bb6

#[test]
fn test_x942_kdf_asn1 () {

    let _sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let _partyu_info = b"1234";
    let _output_no_info =    hex!("45a682e60ab52b1ae3edd2a1da7ec3f3");
    let _output_with_info = hex!("a04e55a7809594a06bf0910ba40e3bb6");

    //let _result_no_info = X963KdfSha256::<U16>::derive(&sharedsecret, &[]);
 //   assert! ( result_no_info == output_no_info.into());

    //let _result_with_info = X963KdfSha256::<U16>::derive(&sharedsecret, partyu_info);
 //   assert! ( result_with_info == output_with_info.into());

}



//
// Couple of test from openssl
//
// openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mode:"EXTRACT_ONLY" -binary HKDF | xxd -p
//  e1c1614719966872e503a0d6ae2832beed08d246c75525cb98fcb4465e958573
//
// openssl kdf -keylen 32 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mode:"EXTRACT_ONLY" -kdfopt hexsalt:6789 -binary HKDF | xxd -p 
//   7936aa2915d2f078eb8a09134848af52567eef7b8cf35546c91b9eefbd2065b1
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -binary HKDF | xxd -p 
//  8d1785397c490fb7c922096d7e996b37
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -binary HKDF | xxd -p
//   068727c63daa10064bb3e694fdceaf65
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mode:EXTRACT_AND_EXPAND -kdfopt hexinfo:123456 -kdfopt hexsalt:6789 -binary HKDF | xxd -p 
//   410f65514d76b1ade8619a8c33a2b4d8
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mode:EXPAND_ONLY -kdfopt hexinfo:123456 -kdfopt hexsalt:6789 -binary HKDF | xxd -p      
//  550eef5a27a22c4e28e37d503ca2b1c8
//
#[test]
#[cfg(all(feature="rustcrypto-sha2", feature="rustcrypto-hmac"))]
fn test_hdkf_kdf () {
    let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let extracted_no_salt = hex!("e1c1614719966872e503a0d6ae2832beed08d246c75525cb98fcb4465e958573");
    let salt = hex!("6789");
    let extracted_with_salt = hex!("7936aa2915d2f078eb8a09134848af52567eef7b8cf35546c91b9eefbd2065b1");
    let partyu_info = hex!("123456");
    let output_no_info =    hex!("8d1785397c490fb7c922096d7e996b37");
    let output_with_info = hex!("068727c63daa10064bb3e694fdceaf65");
    let output_with_info_and_salt = hex!("410f65514d76b1ade8619a8c33a2b4d8");
    let output_with_info_and_salt2 = hex!("410f65514d76b1ade8619a8c33a2b4d851b93ac808c39ba7033618a503ed");
    let output_expand_only = hex!( "550eef5a27a22c4e28e37d503ca2b1c8");

    let result2 = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha256>>::derive_salt_secret::<U32>(&[], &sharedsecret).unwrap();
    assert! ( result2 == extracted_no_salt);

    let result3 = rfc5869_hkdf::HkdfExtract::<HmacReset<Sha256>>::derive_salt_secret::<U32>(&salt, &sharedsecret).unwrap();
    assert! ( result3 == extracted_with_salt);

    let result4 = rfc5869_hkdf::HkdfExpand::<HmacReset<Sha256>>::derive_secret_other::<U16>(&extracted_no_salt, &[]).unwrap();
    assert! ( result4 == output_no_info);

    let result5 = rfc5869_hkdf::HkdfExpand::<HmacReset<Sha256>>::derive_secret_other::<U16>(&extracted_no_salt, &partyu_info).unwrap();
    assert! ( result5 == output_with_info);

    let result6 = rfc5869_hkdf::HkdfExpand::<HmacReset<Sha256>>::derive_secret_other::<U16>(&extracted_with_salt, &partyu_info).unwrap();
    assert! ( result6 == output_with_info_and_salt);

    let result7 = rfc5869_hkdf::Hkdf::<Sha256>::derive_secret_salt_other::<U16>(&sharedsecret, &salt,  &partyu_info).unwrap();
    assert! ( result7 == output_with_info_and_salt);

    let result8 = rfc5869_hkdf::Hkdf::<Sha256>::derive_secret_salt_other::<U30>(&sharedsecret, &salt,  &partyu_info).unwrap();
    assert! ( result8 == output_with_info_and_salt2);

    let result9 = rfc5869_hkdf::HkdfExpand::<HmacReset<Sha256>>::derive_secret_other::<U16>(&sharedsecret, &partyu_info).unwrap();
    assert! ( result9 == output_expand_only);
}


//
// Couple of test from openssl
// Test vector from https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexsecret:00 -kdfopt hexseed:00 -binary TLS1-PRF | xxd -p
//  7a29dae84056ebbf71c406c0a5f032c2  
//
// openssl kdf -keylen 36 -kdfopt digest:SHA2-256 -kdfopt hexsecret:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexseed:9876 -binary TLS1-PRF | xxd -p
//   6d48d4ac7b52f9779f1ba77270c1d3e6
//
// openssl kdf -keylen 80 -kdfopt digest:SHA2-256 -kdfopt hexsecret:9bbe436ba940f017b17652849a71db35 -kdfopt hexseed:74657374206c6162656ca0ba9f936cda311827a6f796ffd5198c -binary TLS1-PRF | xxd -p
//   e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61e
//   db5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797
//   c0564bab4fbc91666e9def9b97fce34f796789ba
//
// openssl kdf -keylen 36 -kdfopt digest:SHA2-256 -kdfopt hexsecret:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexseed:9876 -binary TLS1-PRF | xxd -p
 //   f089fefe45c29d8252ca99fc0c9728217ffe4337ef38e07d0cfd85d113d8bd2f2ac15c0f

#[test]
fn test_tls1_prf_kdf () {
    let shared_secret = hex!("00");
    let seed = hex!("00");
    //let seed = b"master secret\0";
    let r1 = hex!("7a29dae84056ebbf71c406c0a5f032c2");

    let result = rfc5246_tls::Tls1Prf::<HmacReset<Sha256>>::derive_secret_other::<U16>(&shared_secret, &seed).unwrap();
    assert! ( result == r1);

    // Test vectors
    let sharedsecret = hex!("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35");
    let seed = hex!("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c");
    let label = b"test label";
    let output = hex!( "e3 f2 29 ba 72 7b e1 7b  8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a\
    6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab 4f bc 91 66 6e 9d ef 9b\
    97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01 87 34 7b 66 ");

    let result = rfc5246_tls::Tls1Prf::<HmacReset<Sha256>>::derive_secret_others::<U100>(&sharedsecret, [label.as_slice(), seed.as_ref()]).unwrap();
    assert!( result == output);
    
    let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let seed = hex!("9876");
    let output_with_seed = hex!("f089fefe45c29d8252ca99fc0c9728217ffe4337ef38e07d0cfd85d113d8bd2f2ac15c0f");
    let result2 = rfc5246_tls::Tls1Prf::<HmacReset<Sha256>>::derive_secret_other::<U36>(&sharedsecret, &seed).unwrap();
    
    assert!( result2 == output_with_seed);


    // NIST Test Vector - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
    let pre_master_secret = hex!("f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc");
    let server_hello_random = hex!("f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce");
    let client_hello_random = hex!("36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c");
    let server_random = hex!("ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868");
    let client_random = hex!("62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616");
    let master_secret = hex!("202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf");
    let key_block = hex!("d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928");

    let result2 = rfc5246_tls::Tls1Prf::<HmacReset<Sha256>>::derive_secret_others::<U48>(&pre_master_secret, [b"master secret", client_hello_random.as_slice(), &server_hello_random]).unwrap();
    assert! ( result2 == master_secret);

    let result3 = rfc5246_tls::Tls1Prf::<HmacReset<Sha256>>::derive_secret_others::<U128>(&master_secret, [b"key expansion", server_random.as_slice(), &client_random]).unwrap();
    assert! ( result3 == key_block);
    
}

    
//
// Couple of test from openssl
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc  -binary SSKDF | xxd -p  
//   2476f904abde1de5e0ba9d5b0345020c
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -binary SSKDF | xxd -p
//    75607159f86a412bd889ad4c3d52da77
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mac:HMAC -binary SSKDF | xxd -p  
//     be4b2c6ff257c31aae617b7d6a3878a7
//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -kdfopt mac:HMAC -binary SSKDF | xxd -p 
//   989229c5a877a568660dad3cb07f4280
//
// openssl kdf -keylen 80 -kdfopt digest:SHA2-384 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt mac:HMAC -binary SSKDF | xxd -p  
//   51ddd1c15c9d5c473535b3d4501df29498d5f9aa2a36d11711d89dfb6756ab011cbc3b50b84884b862a04ce0db659430e23947c1a1bb52b9e88a0f89c8ec6b384aeba7a35be49bace507d71f4925475a
//
// openssl kdf -keylen 10 -kdfopt digest:SHA2-512 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt hexinfo:123456 -kdfopt mac:HMAC -kdfopt hexsalt:"ABCDEF" -binary SSKDF | xxd -p 
//   4db999bba0b15f1401b5

#[test]
fn test_sskdf_kdf () {

    let sharedsecret = hex!("09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let info = hex!("123456");
    let output_no_info = hex!("2476f904abde1de5e0ba9d5b0345020c");
    let output_with_info = hex!("75607159f86a412bd889ad4c3d52da77");

    let result = nistsp800_56::SskdfHash::<Sha256>::derive_secret_other::<U16> ( &sharedsecret, &[]).unwrap();
    assert! ( result == output_no_info);

    let result2 = nistsp800_56::SskdfHash::<Sha256>::derive_secret_other::<U16> ( &sharedsecret, &info).unwrap();
    assert! ( result2 == output_with_info);

    let output_no_info_hmac = hex!("be4b2c6ff257c31aae617b7d6a3878a7");
    let output_with_info_hmac = hex!("989229c5a877a568660dad3cb07f4280");

    let result3 = nistsp800_56::SskdfMac::<HmacReset<Sha256>>::derive_secret_other::<U16> ( &sharedsecret, &[]).unwrap();
    assert! ( result3 == output_no_info_hmac);

    let result4 = nistsp800_56::SskdfMac::<HmacReset<Sha256>>::derive_secret_other::<U16> ( &sharedsecret, &info).unwrap();
    assert! ( result4 == output_with_info_hmac);

    let output_with_info_hmac384 = hex!("51ddd1c15c9d5c473535b3d4501df29498d5f9aa2a36d11711d89dfb6756ab011cbc3b50b84884b862a04ce0db659430e23947c1a1bb52b9e88a0f89c8ec6b384aeba7a35be49bace507d71f4925475a");
    let result5 = nistsp800_56::SskdfMac::<HmacReset<Sha384>>::derive_secret_other::<U80> ( &sharedsecret, &info).unwrap();
    assert! ( result5 == output_with_info_hmac384);

    let salt = hex!("ABCDEF");
    let output_with_info_hmac512_salt = hex!("4db999bba0b15f1401b5");
    //let result6 = nistsp800_56::SskdfMac::<Hmac<Sha512>>::derive_from_secret_salt_other2_variable ( &sharedsecret, &salt, &info);
    //let result6 = nistsp800_56::SskdfMac::<Hmac<Sha512>>::new_from_slice(&salt).derive_self_secret_other (&sharedsecret, &info);
    let result6 = nistsp800_56::SskdfMac::<HmacReset<Sha512>>::new_with_salt(&salt).derive_self_secret_other::<U10> (&sharedsecret, &info).unwrap();
    
    assert! ( result6 == output_with_info_hmac512_salt);
}

//
// openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt xcghash:01234 -kdfopt session_id:4567 -kdfopt type:A -binary SSHKDF | xxd -p 
//   f3c2fb78cf931bd0fb84dd093baa27e5
// 
// openssl kdf -keylen 80 -kdfopt digest:SHA2-256 -kdfopt hexkey:09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc -kdfopt xcghash:01234 -kdfopt session_id:4567 -kdfopt type:B -binary SSHKDF | xxd -p 
//   c65337e8ed15b0e4cd0661d9f9de21ded7104e7d0bce60afa2f090737e84
//   ef73d12c6c115e11847f45f06592130778fc2709906373066a1715178d5e
//   13bda496dfb6adfe2dc7a8732a20843fcdd62874
#[test]
fn test_sshkdf() {
    let key = hex!( "09abaf6b0893649c6550581fd54ea774492a589cfc4951c3ca360caa4b5581fc");
    let xcghash = b"01234";
    let sessionid = b"4567";
    let ssh_type = 'A' as u8; //b"A";
    let exp_result = hex!( "f3c2fb78cf931bd0fb84dd093baa27e552b72b188d999d0cdfc8050726c39358");

    let result = rfc4253_ssh::SshKdf::<Sha256>::derive::<U32> ( &key, xcghash, ssh_type, sessionid ).unwrap();
    assert! ( result == exp_result);

    let ssh_type2 = 'B' as u8;
    let exp_result2 = hex!("c65337e8ed15b0e4cd0661d9f9de21ded7104e7d0bce60afa2f090737e84"
        "ef73d12c6c115e11847f45f06592130778fc2709906373066a1715178d5e"
        "13bda496dfb6adfe2dc7a8732a20843fcdd62874" );

    let result2 = rfc4253_ssh::SshKdf::<Sha256>::derive::<U80> ( &key, xcghash, ssh_type2, sessionid ).unwrap();

    assert! ( result2 == exp_result2);


    // From NIST Test Vectors - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ssh.zip
    // 
    let k = hex!("0000008100ec6f2c5f0517fd92f730567bd783138302917c277552b1b3fdf2b67d6edb6fa81bd17f7ebbe339b54b171341e6522b91611f8274cc88652a458f8041261040818a268497e949e12f57271318b2b3194c29760cbb767c0fc8833b272994e18682da807e6c9f235d88ef89c203c6f756d25cc2bea199b02c955b8b40cbc04f9208");
    let h = hex!("ee40eef61bea3da8c2b1cec40fc4cdac892a2626");
    let session_id = hex!("ca9aad244e24797fd348d1250387c8aa45a0110a");
    let initial_iv_client_to_server = hex!("55a1015757de84cb");
    let initial_iv_server_to_client = hex!("7e57f61d5735f4fb");
    let enc_key_client_to_server = hex!("dd1c24bde1af845e82207541e3e173aec822fb904a94ae3c");
    let enc_key_server_to_client = hex!("cbbfdc9442af6db7f8c4dcaa4b0b5d0163e0e204476aa2a0");
    let int_key_client_to_server = hex!("e153e04886c0dc446dde9a9b3b13efb77151764d");
    let int_key_server_to_client = hex!("c8e4f61bd6b5abb2c6e06eca7b302349435e4842");

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U8> ( &k, &h, 'A' as u8, &session_id ).unwrap();
    assert! (result2 == initial_iv_client_to_server);

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U8> ( &k, &h, 'B' as u8, &session_id ).unwrap();
    assert! (result2 == initial_iv_server_to_client);

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U24> ( &k, &h, 'C' as u8, &session_id ).unwrap();
    assert! (result2 == enc_key_client_to_server);

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U24> ( &k, &h, 'D' as u8, &session_id ).unwrap();
    assert! (result2 == enc_key_server_to_client);

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U20> ( &k, &h, 'E' as u8, &session_id ).unwrap();
    assert! (result2 == int_key_client_to_server);

    let result2 = rfc4253_ssh::SshKdf::<Sha1>::derive::<U20> ( &k, &h, 'F' as u8, &session_id ).unwrap();
    assert! (result2 == int_key_server_to_client);

        
}

#[cfg(feature = "rustcrypto-cshake")]
#[test]
fn test_cshake_kdf() {
    use kdfs::misc::{CShake128Kdf, CShake256Kdf};
    //COUNT = 511
    //Outputlen = 576

    let msg = hex!("46fb2be061ac51008bd522ede4a65a82");
    let output = hex!("b29362ce87fc3bcae03667aa057a6012e6ade44cb883299aaebed7f617b4063cab6783f12737d0d132cfa3e138bcdcd0928ea2235c120b86d14d11567964486d11b4b4b76d227eff");

    let res1 = CShake128Kdf::derive_secret_other::<U72>(&msg, b"").unwrap();
    // let mut hasher = Shake128::default();
    // hasher.update(&msg);
    // let mut reader = hasher.finalize_xof();
    // let mut res1 = [0u8; 72];
    // reader.read(&mut res1);
    //println! ( "res1={:02X?}", res1);
    assert_eq!(res1.as_slice(), &output);

    // Test vector from NIST for Shake256 (no derivation data)
    let msg = hex!("4a83fecb9bb341ca8290358ca43a4a518a23fd2f491ea2bf62b96016e7cd7df6");
    let output = hex!("a61fc2c5b2");
    let res2 = CShake256Kdf::derive_secret_other::<U5>(&msg, b"").unwrap();
    assert_eq! (res2, output);
}

#[cfg(feature = "rustcrypto-cshake")]
#[test]
fn test_kmac_kdf() {
    let key = hex!("40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F");
    let _data = hex!("00 01 02 03");
    let _s = b"";
    //KMAC128(K, X, L, S):
    // K is a key bit string of any length, including zero.
    // X is the main input bit string. It may be of any length, including zero.
    // L is an integer representing the requested output length8 in bits.
    // S is an optional customization bit string of any length, including zero. If no customization is desired, S is set to the empty string.
    //newX = bytepad(encode_string(K), 168) || X || right_encode(L).
    //return cSHAKE128(newX, L, “KMAC”, S).
    let _encoded_key = hex!("02 01 00 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F");
    let _encoded_key_hdr = _left_encode_header(key.len()*8);

    //let kdf = Kmac
    

}

fn _left_encode_header ( length: usize ) -> Vec<u8> 
{
    let mut v = match length {
        0..=255 => [length as u8].to_vec(),
        0x0100..=0xFFFF => (length as u16).to_be_bytes().to_vec(),
        _ => panic!("unhandled length")
    };
    v.insert(0, v.len() as u8);
    return v;
}



/// openssl kdf -keylen 40 -kdfopt digest:SHA1 -kdfopt hexkey:5E10B967A95606853E528F04262AD18A4767C761163971391E17CB05A21668D4CE2B9F151617408042CE0919583823FD346D1751FBE2341AF2EE0461B62F100FFAD4F723F70C18B38238ED183E9398C8CA517EE0CBBEFFF9C59471FE278093924089480DBC5A38E9A1A97D23038106847D0D22ECF85F49A861821199BAFCB0D74E6ACFFD7D142765EBF4C712414FE4B6AB957F4CB466B46601289BB82060428272842EE28F113CD11F39431CBFFD823254CE472E2105E49B3D7F113B825076E6264585807BC46454665F27C5E4E1A4BD03470486322981FDC894CCA1E2930987C92C15A38BC42EB38810E867C4432F07259EC00CDBBB0FB99E1727C706DA58DD -kdfopt info:"HMAC Key" -binary X942kdf-concat | xxd -p 
///    bc98eb018cb00ee26d1f97a15ae166912a7ac4c5773e6b04e82df1a472324254fb0c21cb5743ddd4

#[test]
fn test_x942_concatkdf2()
{
    // Test vectors from ANSI X9.42 - D.5.1
    let zz = hex!("
        5E10 B967 A956 0685 3E52 8F04 262A D18A 
        4767 C761 1639 7139 1E17 CB05 A216 68D4 
        CE2B 9F15 1617 4080 42CE 0919 5838 23FD 
        346D 1751 FBE2 341A F2EE 0461 B62F 100F 
        FAD4 F723 F70C 18B3 8238 ED18 3E93 98C8 
        CA51 7EE0 CBBE FFF9 C594 71FE 2780 9392 
        4089 480D BC5A 38E9 A1A9 7D23 0381 0684 
        7D0D 22EC F85F 49A8 6182 1199 BAFC B0D7 
        4E6A CFFD 7D14 2765 EBF4 C712 414F E4B6 
        AB95 7F4C B466 B466 0128 9BB8 2060 4282 
        7284 2EE2 8F11 3CD1 1F39 431C BFFD 8232 
        54CE 472E 2105 E49B 3D7F 113B 8250 76E6 
        2645 8580 7BC4 6454 665F 27C5 E4E1 A4BD 
        0347 0486 3229 81FD C894 CCA1 E293 0987 
        C92C 15A3 8BC4 2EB3 8810 E867 C443 2F07 
        259E C00C DBBB 0FB9 9E17 27C7 06DA 58DD");

    let other_info = b"HMAC Key"; 
    let exp_res = hex!("95D6 41F4 2645 88E4 E2B6 E3E9 1345 62BC 1823 69EB");
    // The test vectors have the counter at the end, which is inconsistent with the text
    // To make it work use Okdf5 instead of Okdf2 and reverse the key and other_info fields 
    // https://www.di-mgt.com.au/x942testvectors.html
    let res = Okdf5::<Sha1,1>::derive_secret_other::<U20>(other_info, &zz).unwrap();
    assert! ( res == exp_res);

    let other_info2 = b"TDEA Key";
    let exp_res2 = hex!("EA35 A6C8 84D2 4D73 4793 9E1F DA75 FD79 95CF D4AC D220 8473 2E65 54FA 2CEE 0F69 F012 67A3 214D CCAE");
    let res2 = Okdf5::<Sha1,1>::derive_secret_other::<U40>(other_info2, &zz).unwrap();
    assert! ( res2 == exp_res2);

    let other_info3 = b"HMAC and TDEA Keys";
    let exp_res3 = hex!("F13D BE8D 2C11 526C 6F6E 0BAE 7C88 47AB 5FFA 5844 ECCC 7727 48DB F4B8 D2DF 744D 60E0 4400 C1AA F29E A7E1 EB3D 48B7 146E 8B48 3F49 331C A0DF 5710 5040");    
    let res3 = Okdf5::<Sha1,1>::derive_secret_other::<U60>(other_info3, &zz).unwrap();
    assert! ( res3 == exp_res3);
    
    
}

#[test]
/// Tried and failed to get openssl to recreate the test vector output
/// openssl kdf -keylen 40 -kdfopt digest:SHA1 -kdfopt hexkey:5E10B967A95606853E528F04262AD18A4767C761163971391E17CB05A21668D4CE2B9F151617408042CE0919583823FD346D1751FBE2341AF2EE0461B62F100FFAD4F723F70C18B38238ED183E9398C8CA517EE0CBBEFFF9C59471FE278093924089480DBC5A38E9A1A97D23038106847D0D22ECF85F49A861821199BAFCB0D74E6ACFFD7D142765EBF4C712414FE4B6AB957F4CB466B46601289BB82060428272842EE28F113CD11F39431CBFFD823254CE472E2105E49B3D7F113B825076E6264585807BC46454665F27C5E4E1A4BD03470486322981FDC894CCA1E2930987C92C15A38BC42EB38810E867C4432F07259EC00CDBBB0FB99E1727C706DA58DD -binary -kdfopt cekalg:des3-wrap -kdfopt "supp-privinfo:John Kennedy and Friends" X942kdf-asn1 | xxd -p 
///   e8bcc41fa381a553a7f329623c593ee1b4ac6287b438562a6713bea52c0a91ef06a71efdd64d7b32
fn test_x942_asn1kdf()
{
    // Test vector from X9.42 - D.5.2
    let zz = hex!("5E10 B967 A956 0685 3E52 8F04 262A D18A 4767 C761 1639 7139 1E17 CB05 A216 68D4 CE2B 9F15 1617 4080 42CE 0919 5838 23FD 346D 1751 FBE2 341A F2EE 0461 B62F 100F FAD4 F723 F70C 18B3 8238 ED18 3E93 98C8 CA51 7EE0 CBBE FFF9 C594 71FE 2780 9392 4089 480D BC5A 38E9 A1A9 7D23 0381 0684 7D0D 22EC F85F 49A8 6182 1199 BAFC B0D7 4E6A CFFD 7D14 2765 EBF4 C712 414F E4B6 AB95 7F4C B466 B466 0128 9BB8 2060 4282 7284 2EE2 8F11 3CD1 1F39 431C BFFD 8232 54CE 472E 2105 E49B 3D7F 113B 8250 76E6 2645 8580 7BC4 6454 665F 27C5 E4E1 A4BD 0347 0486 3229 81FD C894 CCA1 E293 0987 C92C 15A3 8BC4 2EB3 8810 E867 C443 2F07 259E C00C DBBB 0FB9 9E17 27C7 06DA 58DD");
    let algorithm_id = hex!("30 09 06 07 2A 86 48 CE 3F 01 02"); // ANS X9.52 Triple-DEA, TCBC mode, 1.2.840.10047.1.2
    let supp_priv_info = hex!("4A6F 686E 204B 656E 6E65 6479 2061 6E64 2046 7269 656E 6473");
    let exp_res = hex!("31B0 CA24 DF4A FDE9 B6D6 44E9 DC3B 030E 429D 7E15 2D90 9C8F BFCA 0A16 AA3E D5EA 2B56 5E12 DE3D FCDC");

    let res = ansi_x9_42::X942Asn1Kdf::<Sha1>::new(&algorithm_id, &[]).derive_self_secret_other::<U40>(&zz, &supp_priv_info).unwrap();
    
    assert! ( res == exp_res);

    // let mut res2 = ansi_x9_42::X942Asn1Kdf::<Sha1, U40>::new(&algorithm_id, &[]);
    // res2.set_secret ( &zz);
    // res2.update ( &supp_priv_info);
    // assert! ( res2.finalize_fixed() == exp_res);

    // id-alg-CMS3DESwrap OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 6 }
    let algorithm_id2 = hex! ("30 0D 06 0B 2A 86 48 86 F7 0D 01 09 10 03 06");
    let res2 = ansi_x9_42::X942Asn1Kdf::<Sha1>::new(&algorithm_id2, &[]).derive_self_secret_other::<U10>(&zz, &supp_priv_info).unwrap();
    println!( "{res2:02X?}");
}

#[test]
fn test_iso18033()
{
    // Test vector C.2.1
    let peh = hex!("4e9752632f973db43ed3d06ffd5bd9e741af0f855cbc556b73ab530affd7850c\
                a4c93d4b91d73b47db8718c05e296151e036cf9ba980cef6563af244438cac1b");
    let z = hex!("5110f7e54f656e70c71ea2067c901570088a1eb1b230000abba1b2df4b774bed54\
                3c0325b7083f2b477d5c02ddcafdfec0725672da2cbed39baf75f02dc078d0");
    let k = hex!("23e41472d780bfbb2daafd85a8fcdf8641fdca4d9f539a4ad175c473ca0f498728\
                931bc311baa2c957ab528935aa22954075a2899ab1ce8ff5ba90a049aeba8cbb9019\
                bccfc5c24c815ac8a1106e163936597b5d06ba4b52377ca48d82621b2768373a2103\
                88998b964c11b0a2780c12c49cdea2cb454543fb3b725b026443d9");
    
    let k_calc = iso18033_2::Kdf1::<Sha1>::derive_secret_other::<U128>(&peh, &z).unwrap();
    assert! ( k_calc == k);

    // Test vector C.2.2
    let peh = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let z = hex!("04ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df047b2e07dd2ffb89"
                            "359945f3d22ca8757874be2536e0f924");
    
    let k = hex!("9a709adeb6c7590ccfc7d594670dd2d74fcdda3f8622f2dbcf0f0c02966d5d9002\
                            db578c989bf4a5cc896d2a11d74e0c51efc1f8ee784897ab9b865a7232b5661b7cac\
                            87cf4150bdf23b015d7b525b797cf6d533e9f6ad49a4c6de5e7089724c9cadf0adf1\
                            3ee51b41be6713653fc1cb2c95a1d1b771cc7429189861d7a829f3");
    
    let k_calc = iso18033_2::Kdf1::<Sha1>::derive_secret_other::<U128>(&peh, &z).unwrap();
    assert! ( k_calc == k);

    // Test vector C.2.3
    let peh = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let z = hex!("02ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df");
    let k = hex!("8fbe0903fac2fa05df02278fe162708fb432f3cbf9bb14138d22be1d279f74bfb9\
                            4f0843a153b708fcc8d9446c76f00e4ccabef85228195f732f4aedc5e48efcf2968c\
                            3a46f2df6f2afcbdf5ef79c958f233c6d208f3a7496e08f505d1c792b314b45ff647\
                            237b0aa186d0cdbab47a00fb4065d62cfc18f8a8d12c78ecbee3fd");
    let k_calc = iso18033_2::Kdf1::<Sha1>::derive_secret_other::<U128>(&peh, &z).unwrap();
    assert! ( k_calc == k);


    // Test vector C.6.2
    let r = hex!("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741\
                    52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    
    let k = hex!("0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840f\
                f32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a\
                25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3\
                837eea4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807");
    
    let k_calc = iso18033_2::Kdf2::<Sha1>::derive_secret_other::<U128>(&r, &[]).unwrap();
    assert! ( k_calc == k );

}



#[test]
fn test_srtp()
{
    // NIST Test Vector https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/srtp.zip
    let k_master = hex!("c4809f6d369888728e26adb532129890");
    let master_salt = hex!("0e23006c6c044f5662400e9d1bd6");
    let _kdr = hex!("000000000000");
    let _index = hex!("487165649cca");
    let exp_k_e = hex!("dc382192ab65108a86b259b61b3af46f");
    let exp_k_a = hex!("b83937fb321792ee87b788193be5a4e3bd326ee4");
    let exp_k_s = hex!( "f1c035c00b5a54a61692c016276c");
    let exp_k_e2 = hex!("ab5be0b456235dcf77d5086929bafb38");
    let exp_k_a2 = hex!("c52fde0b80b0f0bad8d15645cb86e7c7c3d8770e");
    let exp_k_s2 = hex!("deb5f85f81336a965ed32bb7ede8");

    let res = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_other::<U16>(&k_master, &master_salt).unwrap();
    assert! ( res == exp_k_e);

    let key_id = hex!("0000000000000001000000000000");
    //let calc_k_a = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::new_from_slice(&master_salt).derive_self_secret_other(&k_master, &key_id);
    let calc_k_a = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::new_with_salt(&master_salt).derive_self_secret_other::<U20>(&k_master, &key_id).unwrap();
    //println! ( "res={:02X?}", calc_k_a);
    assert! ( calc_k_a == exp_k_a );
   
    let key_id = hex!("0000000000000002000000000000");
    let calc_k_s = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_salt_other::<U14>(&k_master, &master_salt, &key_id).unwrap();
    //println! ( "res={:02X?}", calc_k_s);
    assert! ( calc_k_s == exp_k_s);


    let key_id = hex!("0000000000000000000300000000");
    let calc_k_e2 = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_salt_other::<U16>(&k_master, &master_salt, &key_id).unwrap();
    //println! ( "res={:02X?}", calc_k_e2);
    assert! ( calc_k_e2 == exp_k_e2);


    let key_id = hex!("0000000000000000000400000000");
    let calc_k_a2 = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_salt_other::<U20>(&k_master, &master_salt, &key_id).unwrap();
    println! ( "res={:02X?}", calc_k_a2);
    assert! ( calc_k_a2 == exp_k_a2);

    let key_id = hex!("0000000000000000000500000000");
    let calc_k_s2 = StreamCipherKdf::<ctr::Ctr64BE<Aes128>>::derive_secret_salt_other::<U14>(&k_master, &master_salt, &key_id).unwrap();
    println! ( "res={:02X?}", calc_k_s2);
    assert! ( calc_k_s2 == exp_k_s2);
}

#[test]
fn test_tpm_kdf()
{
    // NIST vector - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tpm.zip
    let auth = hex!("fd771b263f6be051a1d7eb0c5138fbfcafbd49de");
    let nonce_even = hex!("6b8790fd56b2b74734ea97db727ac9eb16e69831");
    let nonce_odd = hex!("4fa48de2db65fa7082f4acc9f85ecc81d40d1793");
	//Nonce_even || Nonce_odd = 6b8790fd56b2b74734ea97db727ac9eb16e698314fa48de2db65fa7082f4acc9f85ecc81d40d1793
    let skey_exp = hex!("c431a158b7b77d7e993515f8ebc2cd6add53b702");

    let skey_calc = Kpf3::<HmacReset<Sha1>, u0, u0>::derive_secret_others::<U20>(&auth, [nonce_even.as_slice(), &nonce_odd]).unwrap();
    println! ( "res={:02X?}", skey_calc);
    assert! ( skey_calc == skey_exp);
}

#[test]
fn test_tpm_ike1()
{
    let cky_i = hex!("382e5c8b0a3fa307");
    let cky_r = hex!("ba4b7616700a2413");
    let ni = hex!("ced5635da6796075");
    let nr = hex!("6244b427712fb776");
    let gxy = hex!("2a2e0bbe8da3657a83f3d35826e49e2d38e557e912a1b9e6c30c63577b3eab715466202862027f2c26f3090743555579611771db0b92bef93834432a3a7762fc8a0f4889fd281d6082770d10a40d7bad61e832f041e620d6787e7f62ab2861ddfbe272e0d9d3cdec5f1bbf750e24b8b32d6d714968ad69ce5086c32ad2742ebc");
// 	Ni_b || Nr_b = ced5635da67960756244b427712fb776
    let skeyid = hex!("dc37ac99de6dcfbd1ee74af7fb36f9b4b0a7829d");
// 	gxy || CKY_I || CKY_R || BYTE(0x00) = 2a2e0bbe8da3657a83f3d35826e49e2d38e557e912a1b9e6c30c63577b3eab715466202862027f2c26f3090743555579611771db0b92bef93834432a3a7762fc8a0f4889fd281d6082770d10a40d7bad61e832f041e620d6787e7f62ab2861ddfbe272e0d9d3cdec5f1bbf750e24b8b32d6d714968ad69ce5086c32ad2742ebc\
//        382e5c8b0a3fa307 ba4b7616700a2413 00
    let skeyid_d = hex!("486293ed547adb562cefdaf43d3d8457b196f2b6");
// 	SKEYID_d || gxy || CKY_I || CKY_R || BYTE(0x01) = 486293ed547adb562cefdaf43d3d8457b196f2b62a2e0bbe8da3657a83f3d35826e49e2d38e557e912a1b9e6c30c63577b3eab715466202862027f2c26f3090743555579611771db0b92bef93834432a3a7762fc8a0f4889fd281d6082770d10a40d7bad61e832f041e620d6787e7f62ab2861ddfbe272e0d9d3cdec5f1bbf750e24b8b32d6d714968ad69ce5086c32ad2742ebc382e5c8b0a3fa307ba4b7616700a241301
    let skeyid_a = hex!("f4053b5ca07e59bb41b8f401037ca90b72b3917e");
// 	SKEYID_a || gxy || CKY_I || CKY_R || BYTE(0x02) = f4053b5ca07e59bb41b8f401037ca90b72b3917e2a2e0bbe8da3657a83f3d35826e49e2d38e557e912a1b9e6c30c63577b3eab715466202862027f2c26f3090743555579611771db0b92bef93834432a3a7762fc8a0f4889fd281d6082770d10a40d7bad61e832f041e620d6787e7f62ab2861ddfbe272e0d9d3cdec5f1bbf750e24b8b32d6d714968ad69ce5086c32ad2742ebc382e5c8b0a3fa307ba4b7616700a241302
    let skeyid_e = hex!("49a1d53a80fb77e663552964fbbcb45092021473");

    let result = Kpf1::<HmacReset<Sha1>,u0>::derive_secrets_others::<U20> ( [ni.as_slice(), &nr], [gxy.as_ref()] ).unwrap();
    println! ( "res={:02X?}", result);
    assert!( result == skeyid );

    let result = Kpf1::<HmacReset<Sha1>,u0>::derive_secret_others::<U20> ( skeyid.as_ref(), [gxy.as_slice(), &cky_i, &cky_r, &[0u8;1]]).unwrap();
    println! ( "res={:02X?}", result);
    assert!( result == skeyid_d );

    let result = Kpf1::<HmacReset<Sha1>,u0>::derive_secret_others::<U20> ( skeyid.as_ref(), [skeyid_d.as_slice(), &gxy, &cky_i, &cky_r, &[1u8;1]]).unwrap();
    println! ( "res={:02X?}", result);
    assert!( result == skeyid_a );
    
    let result = Kpf1::<HmacReset<Sha1>,u0>::derive_secret_others::<U20> ( skeyid.as_ref(), [skeyid_a.as_slice(), &gxy, &cky_i, &cky_r, &[2u8;1]]).unwrap();
    println! ( "res={:02X?}", result);
    assert!( result == skeyid_e );

}

#[test]
fn test_tpm_ike2()
{
    // NIST Test Vectors https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/ikev2.zip
    let ni = hex!("3651fef5c9c35e93");
    let nr = hex!("c09a8b90a3f04d59");
    let nir = hex!("3651fef5c9c35e93c09a8b90a3f04d59");
    let gir = hex!("d084a30166a50fb7325c3960874a839449ef9741c2f4f947d0201dd8c1269273d79509f37e3ca3eb4fa2fe2a28254e289cd3f34dad4eb4df1a07685a4b8a94fa61e2491f7598b3ce65547ff133b3f63d1ac4175eaa695033f3cedb026a6873a36455172a8540b8a5d23a0143bed0390ee49b168269d75fffee9fb62be965993c");
    let gir_new = hex!("52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c2");
    let spii = hex!("8e5c3ae507221684");
    let spir = hex!("b1f201bb155c3acd");
    //     Ni || Nr = 3651fef5c9c35e93c09a8b90a3f04d59
    let skeyseed = hex!("cd2e8050137832245f1dbacc6e4f0a92f94d45d6");
    let res = Ktf1::<HmacReset<Sha1>>::derive_secret_salt_other::<U20>(&[], nir.as_ref(), gir.as_ref()).unwrap();
    assert! ( res == skeyseed);
    
    //     Ni || Nr || SPIi || SPIr = 3651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd
    //     value = 3651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd01
    let t1 = hex!("6f1b12cad3cbe097b35430356d869d54cddb0198");
    let sk_d_calc = Kpf1::<HmacReset<Sha1>, u8>::derive_secret_others::<U20>(&skeyseed, [ni.as_slice(), &nr, &spii, &spir]).unwrap();
    //println! ( "res={:02X?}", dkm_calc);
    assert! ( sk_d_calc == t1 );
    //     value = 6f1b12cad3cbe097b35430356d869d54cddb01983651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd02
    //     T2 = ec859174d53ceb92dddedbe2436db69f60977c58
    //     value = ec859174d53ceb92dddedbe2436db69f60977c583651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd03
    //     T3 = fa63bbb667f8d36920b109baae8f6c61a9ac49fe
    //     value = fa63bbb667f8d36920b109baae8f6c61a9ac49fe3651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd04
    //     T4 = da01843225d080ec5539d5881a25521ffb2a0a91
    //     value = da01843225d080ec5539d5881a25521ffb2a0a913651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd05
    //     T5 = 874a9c0a27fcc2d717eb8963a9e3a89c7ab26475
    //     value = 874a9c0a27fcc2d717eb8963a9e3a89c7ab264753651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd06
    //     T6 = 7284c28cf8c3ca40576f4220b052b1fb8e9ad60b
    //     value = 7284c28cf8c3ca40576f4220b052b1fb8e9ad60b3651fef5c9c35e93c09a8b90a3f04d598e5c3ae507221684b1f201bb155c3acd07
    //     T7 = a3c80557323331a8cbb89f206956088083999609
    
    let dkm_exp = hex!("6f1b12cad3cbe097b35430356d869d54cddb0198ec859174d53ceb92dddedbe2436db69f60977c58fa63bbb667f8d36920b109baae8f6c61a9ac49feda01843225d080ec5539d5881a25521ffb2a0a91874a9c0a27fcc2d717eb8963a9e3a89c7ab264757284c28cf8c3ca40576f4220b052b1fb8e9ad60ba3c80557323331a8cbb89f20");
    let dkm_calc = Kpf1::<HmacReset<Sha1>, u8>::derive_secret_others::<U132>(&skeyseed, [ni.as_slice(), &nr, &spii, &spir]).unwrap();
    //println! ( "res={:02X?}", dkm_calc);
    assert! ( dkm_calc == dkm_exp);

    //     Ni || Nr = 3651fef5c9c35e93c09a8b90a3f04d59
    //     value = 3651fef5c9c35e93c09a8b90a3f04d5901
    //     T1 = 4727dc0ef94eb326ce131cf282fb652faa638ad0
    //     value = 4727dc0ef94eb326ce131cf282fb652faa638ad03651fef5c9c35e93c09a8b90a3f04d5902
    //     T2 = ddae3786a11bcc0309876009f8c485de011ad962
    //     value = ddae3786a11bcc0309876009f8c485de011ad9623651fef5c9c35e93c09a8b90a3f04d5903
    //     T3 = c5b1ca8a41ff8145445749079c5686e26ffebbc3
    //     value = c5b1ca8a41ff8145445749079c5686e26ffebbc33651fef5c9c35e93c09a8b90a3f04d5904
    //     T4 = 42f06981f3da745e11ca0976424d1f8caec623d5
    //     value = 42f06981f3da745e11ca0976424d1f8caec623d53651fef5c9c35e93c09a8b90a3f04d5905
    //     T5 = 9dc7186deb20a27b411d1dcb70a365440bf7de90
    //     value = 9dc7186deb20a27b411d1dcb70a365440bf7de903651fef5c9c35e93c09a8b90a3f04d5906
    //     T6 = 5088b0692e8addc094e18d1939bdb67e89798ca6
    //     value = 5088b0692e8addc094e18d1939bdb67e89798ca63651fef5c9c35e93c09a8b90a3f04d5907
    //     T7 = b239e2ccb81c2409dac0106c3326c6752d5525af
    let dkm_child_sa_exp = hex!("4727dc0ef94eb326ce131cf282fb652faa638ad0ddae3786a11bcc0309876009f8c485de011ad962c5b1ca8a41ff8145445749079c5686e26ffebbc342f06981f3da745e11ca0976424d1f8caec623d59dc7186deb20a27b411d1dcb70a365440bf7de905088b0692e8addc094e18d1939bdb67e89798ca6b239e2ccb81c2409dac0106c");
    let dkm_child_sa_calc = Kpf1::<HmacReset<Sha1>, u8>::derive_secret_others::<U132>(&sk_d_calc, [ni.as_slice(), &nr]).unwrap();
    //println! ( "res={:02X?}", dkm_child_sa_calc);
    assert! ( dkm_child_sa_calc == dkm_child_sa_exp);
    //     g^ir(new) || Ni || Nr = 52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d59
    //     value = 52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5901
    //     T1 = b109c21ad4c0797768c1cec9e63554681e48f224
    //     value = b109c21ad4c0797768c1cec9e63554681e48f22452f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5902
    //     T2 = bca7f23c20c4ea7041983451e9aa1d5408656c8a
    //     value = bca7f23c20c4ea7041983451e9aa1d5408656c8a52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5903
    //     T3 = 975ff1b9d9a12c75ffeb64bdecb30174664cccb4
    //     value = 975ff1b9d9a12c75ffeb64bdecb30174664cccb452f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5904
    //     T4 = e14f1c377b7f6d1525af77c7092aac3e47f917eb
    //     value = e14f1c377b7f6d1525af77c7092aac3e47f917eb52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5905
    //     T5 = ae8297fb5539d2008ce830823a09cc197361d4a2
    //     value = ae8297fb5539d2008ce830823a09cc197361d4a252f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5906
    //     T6 = 89c72745f6ce9fefe812be5bf55b3200fbb82e41
    //     value = 89c72745f6ce9fefe812be5bf55b3200fbb82e4152f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d5907
    //     T7 = a4a40877d3fe106db909707b50fd203b307e81ac
    
    let dkm_child_sa_dh_exp = hex!("b109c21ad4c0797768c1cec9e63554681e48f224bca7f23c20c4ea7041983451e9aa1d5408656c8a975ff1b9d9a12c75ffeb64bdecb30174664cccb4e14f1c377b7f6d1525af77c7092aac3e47f917ebae8297fb5539d2008ce830823a09cc197361d4a289c72745f6ce9fefe812be5bf55b3200fbb82e41a4a40877d3fe106db909707b");
    let dkm_child_sa_dh_calc = Kpf1::<HmacReset<Sha1>, u8>::derive_secret_others::<U132>(&sk_d_calc, [gir_new.as_slice(), &ni, &nr]).unwrap();
    //println! ( "res={:02X?}", dkm_child_sa_dh_calc);
    assert! ( dkm_child_sa_dh_calc == dkm_child_sa_dh_exp);
    //     SK-d = 6f1b12cad3cbe097b35430356d869d54cddb0198
    //     g^ir || Ni || Nr = 52f00ab174c25d5b7139ae5ff4e8e9eddee5992d2e36adf8a559ffd90dab1442e4fbe429d320c0f33552a17d1557fa41ea70e8fb916c4fa27ed52b5f8ebd8461afa78f1159159a64055ac5f6319e29c28eae58cbc6847770f32c3fed1d04750484f854790f95e9ec01bc5bc461f24966462e359511329305038e94deb6dd42c23651fef5c9c35e93c09a8b90a3f04d59
    let skeyseed_rekey_exp = hex!("3b03bce748c96d5e8306918d2ff89b68f0648da3");
    //let skeyseed_rekey_calc = Kpf1::<Hmac<Sha1>, u8, U132>::derive_with_salt(&[&sk_d_calc], &[], &[&gir_new, &ni, &nr]);
    let skeyseed_rekey_calc = Ktf1::<HmacReset<Sha1>>::derive_secret_salt_others::<U20>(&[], sk_d_calc.as_ref(), [gir_new.as_slice(), &ni, &nr]).unwrap();
    assert! ( skeyseed_rekey_calc == skeyseed_rekey_exp);

}


#[test]
/// Output from using CryptoKit x963DerivedSymmetricKey
fn test_apple_x963_kdf()
{
    let input = hex!("aa453db21f99ab4657b35a1aabf102e6625e83c9b157fe735ab1cc68ea7a8434");
    let output = hex!( "0cb0519cd4bd777362cf614127a08b7a89c0e1d5ada8fbb8027a8b08eb161368");

    let output_calc =  ansi_x9_63::X963KdfSha256::derive_secret_other::<U32>(&input, &[]).unwrap();

    assert! ( output_calc == output);

    let input2 = hex!("1771ae06ae0919292716d26d3f7d6fe142563244c65d1dcbe8d8eb5a8b3b2c3c");
    let label = hex!("11223344");
    let output2 = hex!("5760c9a8fd32d80b276dfc37c8cae8e1e2f0441bf6f6e252ab47825dd7053ee3");

    let output_calc2 =  ansi_x9_63::X963KdfSha256::derive_secret_other::<U32>(&input2, &label).unwrap();

    assert! ( output_calc2 == output2);
}

#[test]
/// Output from using CryptoKit x963DerivedSymmetricKey
fn test_apple_hkdf_kdf()
{
    let input = hex!("dbdd90d52f9e4ed9edd285072fcd88ba969c8a21e9e5d58bd8e6d89e289b0a1d");
    let salt = hex!( "123456");
    let shared_info = hex!("11223344");
    let output = hex!( "ebddb279f785c34d8cb5ab78f6147c4268d21633a4abd2cdfbe6ba20e5580983");

    let output_calc = Hkdf::<Sha256>::derive_secret_salt_other::<U32>(&input, &salt, &shared_info).unwrap();

    assert! ( output_calc == output);

}

// https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-sha3-01#name-prf-test-vectors
#[test]
fn test_kmac_128_kdf_a_1_1 ()
{
    //Key (hex):
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    //Input (hex):
    let input = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

    //Customization String (string):
    let customization = b"ikev2 prf";

    //Customization String (hex):
    //696b65763220707266

    //Output (hex):
    let output = hex!("3a8d2a5ead5cd4db448b76a241b078fb444e1faf36eef8e195e275778a169b5f");

    let kdf = Kmac128Kdf::new(customization);
    let output2: Array<u8, U32> = kdf.derive_self_secret_other(&key, &input).unwrap();

    assert_eq!(output2, output)

}


// https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-sha3-01#name-prf-test-vectors
#[test]
fn test_kmac_256_kdf_a_1_2 ()
{
    //Key (hex):
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    //Input (hex):
    let input = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

    //Customization String (string):
    let customization = b"ikev2 prf";

    //Customization String (hex):
    //696b65763220707266

    //Output (hex):
    let output = hex!("9ee1b694eee215b097a71000260a494b22a1d583943b6052281efb16e9481c626ff8ef3aca47e8b290c12801694775d15b2d9fede16639c5fab05d0f12c7b112");

    let kdf = Kmac256Kdf::new(customization);
    let output2: Array<u8, U64> = kdf.derive_self_secret_other(&key, &input).unwrap();

    assert_eq!(output2, output)

}

// https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-sha3-01#name-prf-test-vectors
#[test]
fn test_kmac_128_kdf_a_2_1 ()
{
    //Key (hex):
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    //Input (hex):
    let input = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

    //Customization String (string):
    let customization = b"ikev2 kdf";

    //Customization String (hex):
    //696b657632206b6466

    //Output (hex):
    let output = hex!("067b024ab617ab96ed323faa0992d5b2b469dd2f2bde323a4d5a487eb9d7efc7");

    let kdf = Kmac128Kdf::new(customization);
    let output2: Array<u8, U32> = kdf.derive_self_secret_other(&key, &input).unwrap();

    assert_eq!(output2, output);

    let output3 = hex!("918fcc9584938feadca44878aff97466df6de641863bfa2ff92e8d4f28109195316a4786d33a7a3e7de2cf483d9750f0d5f1f2551b59992a621d44850fb4b730");
    let output4 :Array<u8, U64> = kdf.derive_self_secret_other(&key, &input).unwrap();
    assert_eq!(output4, output3);

    let input2 = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0");

    let output5 = hex!("ce8b6b34301ce350bd04c3a85325ec33e38eafca744abea32ca5fc4196e6db8a9df414304023b3678157ec287f89e3eff15796c8cb82ef55f32b953382aa1808e971a62d3475dad6c00572a3ccd90b82907a6db4e63bfe248e22e8d770c5a08f1543d7a869a6b274ed953beeefcf4a1eaac71b3791278136122ee7f7cfc79145eaf25d1875ef6d8d5761aa3cd487a95b8126758621c4b6f8ab6a4eb0e1b460bf91abd802943a86ba");
    let output6 :Array<u8, U168> = kdf.derive_self_secret_other(&key, &input2).unwrap();
    assert_eq!(output6, output5);

}

// https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-sha3-01#name-prf-test-vectors
#[test]
fn test_kmac_128_kdf_a_3_1 ()
{
    //Key (hex):
    let key = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    //Input (hex):
    let input = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");

    //Customization String (string):
    let customization = b"ikev2 integ";

    //Customization String (hex):
    //696b65763220696e746567

    //Output (hex):
    let output = hex!("1a3d6e9421bf83653d7e876479be427a");

    let kdf = Kmac128Kdf::new(customization);
    let output2: Array<u8, U16> = kdf.derive_self_secret_other(&key, &input).unwrap();

    assert_eq!(output2, output)

}