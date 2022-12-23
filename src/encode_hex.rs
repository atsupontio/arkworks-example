
use std::fmt::Write;
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}


pub fn hexdump_option(bytes: &[u8], max: usize) -> Vec<Option<u8>> {

    let mut sum = Vec::new();

    // println!("{} bytes:", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        // b: &u8 の値を2桁の16進数で表示する
        let a = Some(*b);
        sum.push(a);

    }

    println!("bytes len {:?}", bytes.len());

    let count = max - bytes.len();
    for i in 0..count {
        sum.push(Some(000))
    }

    sum
}

pub fn hexdump(bytes: &[u8], max: usize) -> Vec<u8> {

    let mut sum = Vec::new();

    // println!("{} bytes:", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        // b: &u8 の値を2桁の16進数で表示する
        let a = *b;
        sum.push(a);

    }

    let count = max - bytes.len();
    for i in 0..count {
        sum.push(000)
    }

    sum
}
