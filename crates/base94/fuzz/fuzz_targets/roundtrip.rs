#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only the low byte of kf participates; the first byte drives it.
    let (&kf, payload) = data.split_first().unwrap_or((&0, &[]));
    let kf = u32::from(kf);
    let mut encoded = Vec::new();
    base94_simd::encode_into(&mut encoded, payload, kf);
    assert!(encoded.iter().all(|&c| (0x20..=0x7e).contains(&c)));
    assert_eq!(encoded.len(), base94_simd::encoded_len(payload, kf));
    let mut decoded = Vec::new();
    base94_simd::decode_into(&mut decoded, &encoded, kf).expect("own encoding must decode");
    assert_eq!(decoded, payload);
});
