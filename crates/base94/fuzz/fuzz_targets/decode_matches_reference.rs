#![no_main]

//! Differential fuzzing: the SIMD-assisted decoder must match an independent
//! greedy scalar reference bit-for-bit, including error cases and the
//! "output unchanged on error" contract.

use libfuzzer_sys::fuzz_target;

const ESCAPE_RADIX: u8 = 93;

/// Independent reference: greedy scalar parse (the pre-optimization
/// formulation), written straight from the format definition.
fn decode_reference(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<(), ()> {
    let kf8 = kf as u8;
    let start = out.len();
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c < 0x20 {
            out.truncate(start);
            return Err(());
        }
        let b = c - 0x20;
        if b < ESCAPE_RADIX {
            out.push(b.wrapping_add(kf8));
            i += 1;
            continue;
        }
        if b > 94 {
            out.truncate(start);
            return Err(());
        }
        let Some(&c2) = src.get(i + 1) else {
            out.truncate(start);
            return Err(());
        };
        if c2 < 0x20 {
            out.truncate(start);
            return Err(());
        }
        let b2 = c2 - 0x20;
        if b2 > ESCAPE_RADIX {
            out.truncate(start);
            return Err(());
        }
        if b == 94 && b2 > 0xff - 2 * ESCAPE_RADIX {
            out.truncate(start);
            return Err(());
        }
        let v = u32::from(b - ESCAPE_RADIX + 1) * u32::from(ESCAPE_RADIX) + u32::from(b2);
        out.push((v as u8).wrapping_add(kf8));
        i += 2;
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let (&kf, input) = data.split_first().unwrap_or((&0, &[]));
    let kf = u32::from(kf);
    let mut got = Vec::new();
    let mut want = Vec::new();
    let a = base94_simd::decode_into(&mut got, input, kf);
    let b = decode_reference(&mut want, input, kf);
    assert_eq!(a.is_ok(), b.is_ok(), "ok-ness diverged on {input:?} kf={kf}");
    if a.is_ok() {
        assert_eq!(got, want, "output diverged on {input:?} kf={kf}");
    } else {
        assert!(got.is_empty(), "output must be unchanged on error");
    }
});
